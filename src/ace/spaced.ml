open Cmdliner

let version = Version.string

let sk = Arg.(required & pos 0 (some string) None & info []
                ~docv:"SECRET_KEY"
                ~doc:"crypto_box secret key for this agent")

let pk = Arg.(required & pos 1 (some string) None & info []
                ~docv:"PUBLIC_KEY"
                ~doc:"crypto_box public key for this agent")

let server_pk = Arg.(required & pos 2 (some string) None & info []
                       ~docv:"CLOUD_BASE_PUBLIC_KEY"
                       ~doc:"crypto_box public key for the cloud base")

let domain = Arg.(required & pos 3 (some string) None & info []
                    ~docv:"DOMAIN"
                    ~doc:"your signpost")

let serve sk pk server_pk domain =
  Lwt_main.run begin
    Sodium.Box.(Aced.serve
                  (Bytes.to_secret_key (Hex.to_string (`Hex sk)))
                  (Bytes.to_public_key (Hex.to_string (`Hex pk)))
                  (Bytes.to_public_key (Hex.to_string (`Hex server_pk)))
                  (Dns.Name.string_to_domain_name domain))
  end

let default_cmd =
  let doc = "start the local resolver daemon" in
  let man = [
    `S "DESCRIPTION";
    `P "$(b,spaced) is the Signpost Ace Daemon, a local DNS resolver that encrypts DNS traffic with DNSCurve to a remote Signpost Base Daemon for further resolution.";
    `S "COMMON OPTIONS";
    `P "$(b,--help) will show more help for each sub-command.";
    `S "BUGS";
    `P "Email bug reports to <mailto:sheets@alum.mit.edu>, or report them online at <https://github.com/dsheets/signpost/>."
  ] in
  Term.(pure serve $ sk $ pk $ server_pk $ domain),
  Term.info "spaced" ~version ~doc ~man

;;
Printexc.record_backtrace true;

match Term.eval default_cmd with
| `Error _ -> exit 1
| _ -> exit 0
