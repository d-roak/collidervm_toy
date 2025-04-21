#!/bin/bash

set -euo pipefail

################################################################################
#                                  CONSTANTS                                     #
################################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)" # Assumes scripts/demo relative to workspace root
readonly DEFAULT_PARAMS_FILE="demo_params.env"
readonly DEFAULT_RANDOMIZER=42
readonly DEMO_OUTPUT_DIR="target/demo" # Matches the output dir in src/bin/demo.rs

################################################################################
#                                  FUNCTIONS                                     #
################################################################################

print_usage() {
  echo "Usage: $0 [options]"
  echo
  echo "Run the ColliderVM demo end-to-end."
  echo
  echo "Options:"
  echo "  -b, --break           Add breakpoints between steps (press Enter to continue)"
  echo "  -p, --params          Parameters file (default: $DEFAULT_PARAMS_FILE)"
  echo "  -r, --randomizer      Randomizer value for key generation (default: $DEFAULT_RANDOMIZER)"
  echo "  -d, --dry-run         Perform a dry run for sending transactions"
  echo "  -h, --help            Show this help message"
}

log() {
  local msg=$1
  local timestamp
  timestamp=$(date +'%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $msg"
}

error() {
  log "ERROR: $1" >&2
  exit 1
}

print_section() {
  local title=$1
  local line="=================================================================="
  echo
  echo "$line"
  echo "                         $title"
  echo "$line"
  echo
}

wait_for_user() {
  if [[ $use_breakpoints == true ]]; then
    read -r -p "Press Enter to continue..."
  fi
}

run_script() {
  local script_path=$1
  shift # Remove script path from args
  local args=("$@")
  local description=$1 # Use the first remaining arg as description

  log "Running: $description"
  log "Script: $script_path ${args[*]}"

  if ! "$script_path" "${args[@]}"; then
    error "Failed to execute: $script_path"
  fi

  log "Successfully completed: $description"
}

save_param() {
  local param_name=$1
  local param_value=$2
  local output_file=$3

  echo "export ${param_name}="${param_value}"" >> "$output_file"
  log "Saved to $output_file: $param_name=$param_value"
}

################################################################################
#                              PARSE ARGUMENTS                                   #
################################################################################

use_breakpoints=false
params_file="$DEFAULT_PARAMS_FILE"
randomizer=$DEFAULT_RANDOMIZER
dry_run_send=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--break)
      use_breakpoints=true
      shift
      ;;
    -p|--params)
      params_file=$2
      shift 2
      ;;
    -r|--randomizer)
      randomizer=$2
      shift 2
      ;;
    -d|--dry-run)
      dry_run_send=true
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      print_usage
      error "Unknown option: $1"
      ;;
  esac
done

################################################################################
#                              INITIALIZATION                                    #
################################################################################

cd "$WORKSPACE_DIR" || error "Failed to change directory to $WORKSPACE_DIR"

log "Starting ColliderVM Demo Orchestration"
log "Parameters file: $params_file"
log "Using randomizer value: $randomizer"
[[ "$use_breakpoints" == true ]] && log "Breakpoints enabled."
[[ "$dry_run_send" == true ]] && log "Send transactions in DRY RUN mode."

# Initialize params file
log "Initializing parameters file: $params_file"
> "$params_file"
save_param "RANDOMIZER" "$randomizer" "$params_file"
save_param "PARAMS_FILE" "$params_file" "$params_file" # Save the params file location itself

################################################################################
#                   STEP 1: GENERATE SIGNER/OPERATOR KEYS                      #
################################################################################

print_section "STEP 1: GENERATING DEMO KEYS & ADDRESSES"

log "Generating Signer and Operator keys and addresses using collidervm_demo..."
# We run the demo binary once without funding to get the addresses printed
# In a real scenario, you might have a dedicated key generation tool or read from config
# For this demo, we capture the output of the first run
# We assume the binary prints addresses in a predictable format (modify parsing if needed)

# Run the command and capture its output
# Assuming the binary is built and in the target/debug or target/release path
# Adjust CARGO_TARGET_DIR if needed
demo_bin_path="${CARGO_TARGET_DIR:-target/debug}/demo"
if [ ! -x "$demo_bin_path" ]; then
    demo_bin_path="${CARGO_TARGET_DIR:-target/release}/demo"
fi

if [ ! -x "$demo_bin_path" ]; then
    log "Attempting to build the demo binary first..."
    if cargo build --bin collidervm_demo; then
        log "Build successful."
        demo_bin_path="${CARGO_TARGET_DIR:-target/debug}/collidervm_demo" # Re-check debug path first
         if [ ! -x "$demo_bin_path" ]; then
             demo_bin_path="${CARGO_TARGET_DIR:-target/release}/collidervm_demo"
         fi
         if [ ! -x "$demo_bin_path" ]; then
             error "Could not find demo binary 'collidervm_demo' even after building."
         fi
    else
        error "Failed to build demo binary 'collidervm_demo'. Please build it first."
    fi
fi


log "Running '$demo_bin_path' to generate keys/addresses (no funding yet)..."
key_gen_output=$("$demo_bin_path" --x 114) # Use a default 'x' value just to trigger keygen

# Extract addresses - THIS IS FRAGILE and depends on the exact output format
signer_address=$(echo "$key_gen_output" | grep 'Signer  →' | awk '{print $3}')
operator_address=$(echo "$key_gen_output" | grep 'Operator→' | awk '{print $3}')
signer_wif=$(echo "$key_gen_output" | grep 'Signer  →' | awk '{print $5}' | tr -d '()')
operator_wif=$(echo "$key_gen_output" | grep 'Operator→' | awk '{print $5}' | tr -d '()')

if [[ -z "$signer_address" ]] || [[ -z "$operator_address" ]]; then
  error "Failed to extract addresses from '$demo_bin_path' output. Output was: $key_gen_output"
fi

# Save addresses and WIFs to params file
save_param "SIGNER_ADDRESS" "$signer_address" "$params_file"
save_param "OPERATOR_ADDRESS" "$operator_address" "$params_file"
save_param "SIGNER_WIF" "$signer_wif" "$params_file"
save_param "OPERATOR_WIF" "$operator_wif" "$params_file"
log "Extracted Signer Address: $signer_address"
log "Extracted Operator Address: $operator_address"

wait_for_user

################################################################################
#                         STEP 2: SETUP INITIAL STATE                           #
################################################################################

print_section "STEP 2: SETTING UP INITIAL FUNDING TRANSACTION"

# Note: The demo binary expects funding to the SIGNER address.
# The setup_initial_state.sh script will handle funding this address.
run_script "$SCRIPT_DIR/setup_initial_state.sh" "Setting up initial funding transaction" -o "$params_file"
wait_for_user

# Source the updated parameters file as setup_initial_state.sh adds variables
log "Reloading parameters from $params_file"
source "$params_file" || error "Failed to source parameters file: $params_file"

# Verify necessary variables are set
if [[ -z "${FUNDING_TXID:-}" ]] || [[ -z "${FUNDING_VOUT:-}" ]]; then
  error "Required variables (FUNDING_TXID, FUNDING_VOUT) not found in $params_file after setup script."
fi

################################################################################
#                   STEP 3: GENERATE F1/F2 TRANSACTIONS                        #
################################################################################

print_section "STEP 3: GENERATING F1 & F2 TRANSACTIONS"

log "Running '$demo_bin_path' with funding info to generate transaction files..."
# Use a default value for x, or allow overriding via script args if needed later
input_x=114 # Example value that satisfies F1 > 100 and F2 < 200 checks in demo
log "Using input x = $input_x"

# Run the demo binary with funding details
run_command="$demo_bin_path --x $input_x -f $FUNDING_TXID --funding-vout $FUNDING_VOUT"
log "Executing: $run_command"
if ! eval "$run_command"; then
    error "Failed to generate F1/F2 transactions using '$demo_bin_path'."
fi

# Check if output directory and files exist
if [[ ! -d "$DEMO_OUTPUT_DIR" ]] || [[ ! -f "$DEMO_OUTPUT_DIR/f1.tx" ]] || [[ ! -f "$DEMO_OUTPUT_DIR/f2.tx" ]]; then
    error "Expected transaction files (f1.tx, f2.tx) not found in $DEMO_OUTPUT_DIR after running demo binary."
fi

log "F1 and F2 transaction files generated successfully in $DEMO_OUTPUT_DIR."
wait_for_user

################################################################################
#                         STEP 4: SEND DEMO TRANSACTIONS                        #
################################################################################

print_section "STEP 4: SENDING F1 & F2 TRANSACTIONS"

send_script_args=("$SCRIPT_DIR/send_demo_transactions.sh")
[[ "$dry_run_send" == true ]] && send_script_args+=("--dry-run")
send_script_args+=("$DEMO_OUTPUT_DIR") # Pass the directory containing the tx files

run_script "${send_script_args[@]}" "Sending F1 and F2 transactions"

################################################################################
#                                 SUMMARY                                        #
################################################################################

print_section "DEMO COMPLETED"

log "ColliderVM Demo orchestration completed."
log "Parameters saved to: $params_file"
log "Check the output of bitcoin-cli or a block explorer for transaction confirmations."

exit 0 