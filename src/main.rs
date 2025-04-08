#![feature(proc_macro_hygiene)]

use bitcoin_script::script;
use bitcoin_script_dsl::treepp::*;
use bitcoin_scriptexec::execute_script;

fn main() {
    let script = script!(1 2 OP_ADD 3 OP_EQUAL);
    let result = execute_script(script);
    assert!(result.success);
}
