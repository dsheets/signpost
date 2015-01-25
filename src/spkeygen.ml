open Cmdliner
module Base16_of = Base16.To_string

let version = Version.string

let keygen () =
  let (sk,pk) = Sodium.Box.random_keypair () in
  let pk_s = (Base16_of.t (Sodium.Box.Bytes.of_public_key pk)) in
  let sk_s = (Base16_of.t (Sodium.Box.Bytes.of_secret_key sk)) in
  Printf.printf "Public key: %s\n" pk_s;
  Printf.printf "Secret key: %s\n" sk_s;
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
