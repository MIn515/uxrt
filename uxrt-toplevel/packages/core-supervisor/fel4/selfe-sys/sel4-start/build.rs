use std::env;
extern crate selfe_config;
use selfe_config::build_helpers::*;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "sel4"{
        return();                                                             
    } 
    BuildEnv::request_reruns();
    let config = load_config_from_env_or_default();
    config.print_boolean_feature_flags();
}
