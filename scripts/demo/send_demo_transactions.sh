#!/bin/bash

set -euo pipefail

# Load .env file if it exists, for BITCOIN_CLI_CMD_DEMO
if [[ -f .env ]]; then
  source .env
fi

################################################################################
#                                  CONSTANTS                                     #
################################################################################

# Default command for bitcoin-cli. Override with BITCOIN_CLI_CMD_DEMO env var.
readonly DEFAULT_BITCOIN_CLI="bitcoin-cli -signet"
readonly DRY_RUN=0
readonly LIVE_RUN=1
readonly DEFAULT_WAIT_CONFIRMATION=true # Set to false to skip waiting for f1 confirmation

################################################################################
#                                  FUNCTIONS                                     #
################################################################################

print_usage() {
  echo "Usage: $0 [-d|--dry-run] [-w|--no-wait] <tx_directory>"
  echo
  echo "Send F1 and F2 transactions from the specified directory."
  echo
  echo "Arguments:"
  echo "  tx_directory    Directory containing transaction files (f1.tx, f2.tx)"
  echo
  echo "Options:"
  echo "  -d, --dry-run     Simulate sending transactions without actually sending them"
  echo "  -w, --no-wait     Do not wait for F1 confirmation before sending F2 (default: wait)"
  echo
  echo "Environment variables:"
  echo "  BITCOIN_CLI_CMD_DEMO  Override default bitcoin-cli command (default: '$DEFAULT_BITCOIN_CLI')"
  exit 1
}

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [send_demo_txs] $1"
}

error() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [send_demo_txs] ERROR: $1" >&2
  exit 1
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to check if jq is installed
check_jq() {
  if ! command_exists jq; then
    error "jq is not installed. Please install jq (e.g., 'sudo apt-get install jq' or 'brew install jq')."
  fi
}

# Function to wait for transaction confirmation
wait_for_confirmation() {
    local txid=$1
    local tx_name=$2
    local confirmations_needed=1
    log "Waiting for $confirmations_needed confirmation(s) for $tx_name (TXID: $txid)... (This might take a while on Signet)"
    while true; do
        local confirmations
        # Check if the transaction exists and get confirmations
        confirmations=$($bitcoin_cli gettransaction "$txid" 2>/dev/null | jq -r '.confirmations // 0')

        if [[ "$?" -eq 0 && "$confirmations" -ge "$confirmations_needed" ]]; then
            log "$tx_name (TXID: $txid) has $confirmations confirmation(s)."
            break
        fi
        log "$tx_name (TXID: $txid) not confirmed yet ($confirmations/$confirmations_needed confirmations). Checking again in 15 seconds..."
        sleep 15
    done
}

send_transaction_file() {
  local tx_file=$1
  local tx_name=$2
  local run_mode=$3

  if [[ ! -f "$tx_file" ]]; then
      error "Transaction file not found: $tx_file"
  fi

  local raw_tx
  raw_tx=$(cat "$tx_file")
  if [[ -z "$raw_tx" ]]; then
    error "Empty transaction data in $tx_file"
  fi

  log "Sending $tx_name transaction from $tx_file..."

  if [[ $run_mode -eq $DRY_RUN ]]; then
    local simulated_txid="${tx_name}_simulated_txid_$(date +%s)"
    log "[DRY RUN] Would execute: $bitcoin_cli sendrawtransaction \"<hex from $tx_file>\""
    log "[DRY RUN] Simulating successful broadcast for $tx_name: $simulated_txid"
    echo "$simulated_txid"
    return 0
  fi

  local tx_id
  tx_id=$($bitcoin_cli sendrawtransaction "$raw_tx")

  if [[ -n "$tx_id" ]]; then
    log "$tx_name transaction broadcast successfully. TXID: $tx_id"
    echo "$tx_id"
    return 0
  else
    error "Failed to send transaction $tx_name from $tx_file using '$bitcoin_cli'."
  fi
}

################################################################################
#                              PARSE ARGUMENTS                                   #
################################################################################

run_mode=$LIVE_RUN
wait_confirm=$DEFAULT_WAIT_CONFIRMATION
tx_directory=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--dry-run)
      run_mode=$DRY_RUN
      shift
      ;;
    -w|--no-wait)
      wait_confirm=false
      shift
      ;;
    *)
      # Assume the last argument is the directory
      if [[ -z "$tx_directory" ]]; then
          tx_directory=$1
      else
          # If directory already set, it's an unknown arg
          print_usage
      fi
      shift
      ;;
  esac
done

# Validate tx_directory was provided
if [[ -z "$tx_directory" ]]; then
  error "Transaction directory must be specified."
fi

# Validate directory exists
if [[ ! -d "$tx_directory" ]]; then
    error "Specified directory does not exist: $tx_directory"
fi

# Check dependencies for live mode
if [[ $run_mode -eq $LIVE_RUN ]]; then
  check_jq
fi

################################################################################
#                              INITIALIZATION                                    #
################################################################################

log "Starting transaction sending process"
[[ $run_mode -eq $DRY_RUN ]] && log "Running in DRY RUN mode - No transactions will be broadcast."
log "Using transaction directory: $tx_directory"

# Set bitcoin-cli command
bitcoin_cli=${BITCOIN_CLI_CMD_DEMO:-$DEFAULT_BITCOIN_CLI}
log "Using bitcoin-cli command: $bitcoin_cli"

# Verify bitcoin-cli works for live mode
if [[ $run_mode -eq $LIVE_RUN ]]; then
  if ! $bitcoin_cli getblockchaininfo > /dev/null 2>&1; then
      error "Failed to execute bitcoin-cli command: $bitcoin_cli. Check configuration and node status."
  fi
fi

################################################################################
#                              SEND TRANSACTIONS                               #
################################################################################

# Send F1
tx_f1_file="$tx_directory/f1.tx"
# Capture the output of send_transaction_file in a variable to prevent log message interleaving
tx_f1_id=$(send_transaction_file "$tx_f1_file" "F1" "$run_mode")

# Optionally wait for F1 confirmation
if [[ "$wait_confirm" == true && "$run_mode" == $LIVE_RUN ]]; then
    wait_for_confirmation "$tx_f1_id" "F1"
elif [[ "$wait_confirm" == true && "$run_mode" == $DRY_RUN ]]; then
    log "[DRY RUN] Would wait for F1 confirmation (TXID: $tx_f1_id)"
    # Simulate a short wait in dry run mode
    sleep 2
fi

# Send F2
tx_f2_file="$tx_directory/f2.tx"
# Capture the output of send_transaction_file in a variable to prevent log message interleaving
tx_f2_id=$(send_transaction_file "$tx_f2_file" "F2" "$run_mode")

################################################################################
#                                  SUMMARY                                       #
################################################################################

log "Transaction sending process completed!"
log "Summary:"
log "  F1 TXID: $tx_f1_id"
log "  F2 TXID: $tx_f2_id"
[[ $run_mode -eq $DRY_RUN ]] && log "  Mode: DRY RUN (no transactions were actually broadcast)"
log "Check the output of bitcoin-cli or a block explorer for transaction status." 