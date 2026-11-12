'use strict'
const { Interface, getAddress, isAddress, id, zeroPadValue, decodeBytes32String, Transaction, keccak256 } = require('ethers')
const { fromHex, hexQuantity, unsigned, parseAmount } = require('../account-common/amounts.cjs')
const { keyFor } = require('../account-common/keys.cjs')
const ERC20 = new Interface(['function balanceOf(address) view returns (uint256)', 'function decimals() view returns (uint8)',
  'function name() view returns (string)', 'function symbol() view returns (string)', 'function transfer(address,uint256) returns (bool)'])
const TRANSFER = id('Transfer(address,address,uint256)')
function evmAdapter(network, config, transport) {
  const rpc = transport.rpc
  const normalize = value => getAddress(value)
  async function head() {
    // Only height is used by the bounded log watcher. Downloading an entire
    // transaction list here made every Polygon balance depend on a slow call.
    const [chain, number] = await Promise.all([rpc('eth_chainId'), rpc('eth_blockNumber')])
    if (fromHex(chain) !== BigInt(config.chainId)) throw Error('Unexpected EVM network')
    const height = Number(fromHex(number))
    if (!Number.isSafeInteger(height)) throw Error('Invalid EVM height')
    // PublicNode Arbitrum rejects historical/finalized state reads without
    // archive access. Read current state explicitly; do not claim finality.
    return { height, tag: 'latest' }
  }
  async function call(contract, method, args, tag) {
    const value = await rpc('eth_call', [{ to: normalize(contract), data: ERC20.encodeFunctionData(method, args) }, tag])
    try { return ERC20.decodeFunctionResult(method, value)[0] }
    catch (error) {
      if (['symbol', 'name'].includes(method) && /^0x[0-9a-fA-F]{64}$/.test(value)) return decodeBytes32String(value)
      throw error
    }
  }
  async function token(contract, owner, block, previous = {}) {
    contract = normalize(contract)
    const [balance, rawDecimals, rawSymbol, rawName] = await Promise.all([
      call(contract, 'balanceOf', [owner], block.tag), call(contract, 'decimals', [], block.tag),
      call(contract, 'symbol', [], block.tag).catch(() => null), call(contract, 'name', [], block.tag).catch(() => null),
    ])
    const decimals = Number(rawDecimals)
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) throw Error('Invalid token decimals')
    const sameToken = previous.id === contract
    const symbol = rawSymbol ?? (sameToken ? previous.symbol : null) ?? contract.slice(0, 10)
    const name = rawName ?? (sameToken ? previous.name : null) ?? symbol
    return { id: contract, name, symbol, decimals, atomic: unsigned(balance.toString()).toString(), complete: true, standard: 'ERC-20' }
  }
  async function discover(owner, state, block) {
    // PublicNode allows an address-filtered transfer query over ONE block. Only
    // sample the last two blocks; never label this a historical/full scan.
    // Re-reading the previous block catches logs added after its first read.
    // Fast chains can produce more blocks than this bounded watcher covers.
    const start = Math.max(0, block.height - 1)
    const end = block.height, candidates = new Set()
    const topic = zeroPadValue(owner, 32).toLowerCase()
    for (let height = start; height <= end; height++) {
      for (const topics of [[TRANSFER, null, topic], [TRANSFER, topic]]) {
        const logs = await rpc('eth_getLogs', [{ fromBlock: hexQuantity(height), toBlock: hexQuantity(height), topics }])
        if (!Array.isArray(logs)) throw Error('Incomplete transfer log response')
        for (const log of logs) {
          // ERC-721 has four topics. It is not an ERC-20 balance.
          if (log.removed === false && log.topics?.length === 3 && /^0x[0-9a-fA-F]{64}$/.test(log.data) && isAddress(log.address)) candidates.add(normalize(log.address))
        }
      }
    }
    return { candidates: [...candidates], cursor: end, complete: false,
      reason: 'limited-recent-block-watch' }
  }
  async function prepare({ owner, to, amount, asset, max }) {
    owner = normalize(owner); to = normalize(to)
    const [nativeBalance, gasPrice, nonce, tokenBalance] = await Promise.all([
      rpc('eth_getBalance', [owner, 'pending']).then(fromHex), rpc('eth_gasPrice').then(fromHex),
      rpc('eth_getTransactionCount', [owner, 'pending']).then(fromHex),
      asset ? call(asset.id, 'balanceOf', [owner], 'pending').then(value => unsigned(value.toString())) : null,
    ])
    let value = max ? (asset ? tokenBalance : 1n) : parseAmount(amount, asset?.decimals ?? 18)
    if (value <= 0n) throw Error('Amount must be positive')
    if (!gasPrice) throw Error('Gas price unavailable')
    if (nonce > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Invalid account nonce')
    const tx = { from: owner, to: asset ? normalize(asset.id) : to, value: hexQuantity(asset ? 0n : value),
      data: asset ? ERC20.encodeFunctionData('transfer', [to, value]) : '0x', gasPrice: hexQuantity(gasPrice) }
    if (asset) {
      const simulation = await rpc('eth_call', [tx, 'pending'])
      // Older ERC-20 contracts may return no value; an explicit false is a
      // rejected transfer even when eth_estimateGas reports no EVM revert.
      if (simulation !== '0x' && ERC20.decodeFunctionResult('transfer', simulation)[0] !== true) throw Error('Token rejected transfer simulation')
    }
    const estimate = fromHex(await rpc('eth_estimateGas', [tx]))
    // Arbitrum's estimate includes its L1 posting component. Keep an explicit
    // 25% ceiling; the signed gas limit and displayed maximum fee agree.
    const gas = (estimate * 125n + 99n) / 100n, fee = gas * gasPrice
    if (max && !asset) { value = nativeBalance > fee ? nativeBalance - fee : 0n; tx.value = hexQuantity(value) }
    if (!value || nativeBalance < fee + (asset ? 0n : value)) throw Error('Insufficient native balance including maximum network fee')
    if (asset && value > tokenBalance) throw Error('Insufficient token balance')
    // Re-estimate the exact MAX payload. A destination contract may depend on value.
    if (fromHex(await rpc('eth_estimateGas', [tx])) > gas) throw Error('Gas estimate changed; prepare the transfer again')
    return { atomic: value.toString(), feeAtomic: fee.toString(), nativeRequired: fee.toString(),
      unsigned: { to: tx.to, value: asset ? '0' : value.toString(), data: tx.data, nonce: Number(nonce),
        chainId: config.chainId, type: 0, gasLimit: gas.toString(), gasPrice: gasPrice.toString() } }
  }
  async function sign(plan, mnemonic) {
    if (fromHex(await rpc('eth_getTransactionCount', [plan.owner, 'pending'])) !== BigInt(plan.unsigned.nonce)) throw Error('Account nonce changed; review a fresh transfer')
    const key = keyFor(network, mnemonic)
    if (key.address !== plan.owner) throw Error('Transfer wallet changed')
    const serialized = await key.signTransaction(plan.unsigned)
    const parsed = Transaction.from(serialized)
    if (parsed.from !== key.address || parsed.chainId !== BigInt(config.chainId)) throw Error('Signed transaction identity mismatch')
    return { serialized, txid: keccak256(serialized) }
  }
  async function receipt(txid) {
    const data = await rpc('eth_getTransactionReceipt', [txid])
    if (!data) return 'unknown'
    if (data.transactionHash?.toLowerCase() !== txid.toLowerCase() || !data.blockHash) throw Error('Invalid transaction receipt')
    const status = fromHex(data.status)
    if (status !== 0n && status !== 1n) throw Error('Invalid transaction status')
    const finalized = await rpc('eth_getBlockByNumber', ['finalized', false])
    if (fromHex(data.blockNumber) > fromHex(finalized?.number)) return 'submitted'
    const canonical = await rpc('eth_getBlockByNumber', [data.blockNumber, false])
    if (canonical?.hash !== data.blockHash) return 'unknown'
    return status === 1n ? 'confirmed' : 'failed'
  }
  return { normalize, validate: isAddress, head, token, discover, prepare, sign, receipt,
    balance: async (owner, block) => fromHex(await rpc('eth_getBalance', [owner, block.tag])).toString() }
}
module.exports = { evmAdapter, ERC20 }
