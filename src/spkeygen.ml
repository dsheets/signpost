open Cmdliner
module Crypto = Sodium.Make(Sodium.Serialize.String)
module Base16_of = Base16.To_string

let version = Version.string

let keygen () =
  let (pk,sk) = Crypto.box_keypair () in
  Printf.printf "Public key: %s\n" (Base16_of.t (Crypto.box_write_key pk));
  Printf.printf "Secret key: %s\n" (Base16_of.t (Crypto.box_write_key sk));
  ()

let default_cmd =
  let doc = "generate a crypto_box keypair for use with a Signpost" in
  let man = [
    `S "DESCRIPTION";
    `P "$(b,spkeygen) is the Signpost Key Generator, an identity creation tool for secure communications with Signpost.";
    `S "COMMON OPTIONS";
    `P "$(b,--help) will show more help for each sub-command.";
    `S "BUGS";
    `P "Email bug reports to <mailto:sheets@alum.mit.edu>, or report them online at <https://github.com/dsheets/signpost/>."
  ] in
  Term.(pure keygen $ pure ()),
  Term.info "spkeygen" ~version ~doc ~man

;;
Printexc.record_backtrace true;

match Term.eval default_cmd with
| `Error _ -> exit 1
| _ -> exit 0
