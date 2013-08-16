open Cmdliner
module Crypto = Sodium.Make(Sodium.Serialize.String)
module Base16_of = Base16.To_string
module Ipv4 = Ipaddr.V4

let version = Version.string

let sk = Arg.(required & pos 0 (some string) None & info []
                ~docv:"SECRET_KEY"
                ~doc:"crypto_box secret key for this base")

let pk = Arg.(required & pos 1 (some string) None & info []
                ~docv:"PUBLIC_KEY"
                ~doc:"crypto_box public key for this base")

let resolv_ip = Arg.(required & pos 2 (some string) None & info []
                       ~docv:"RESOLV_IP"
                       ~doc:"the IPv4 address of this base")

let zone = Arg.(required & pos 3 (some string) None & info []
                  ~docv:"ZONE"
                  ~doc:"the SOA zone of this base")

let client_pk = Arg.(required & pos 4 (some string) None & info []
                       ~docv:"CLIENT_PUBLIC_KEY"
                       ~doc:"crypto_box public key for DNS tunneling")

let serve sk pk resolv_ip zone client_pk =
  Crypto.(Based.serve
            (box_read_secret_key (Base16_of.string sk))
            (box_read_public_key (Base16_of.string pk))
            resolv_ip
            (Dns.Name.string_to_domain_name zone)
            (box_read_public_key (Base16_of.string client_pk))
  )

let default_cmd =
  let doc = "start the tunnel egress daemon" in
  let man = [
    `S "DESCRIPTION";
    `P "$(b,spbased) is the Signpost Base Daemon, a cloud-based DNS tunnel egress for DNSCurve-encrypted traffic.";
    `S "COMMON OPTIONS";
    `P "$(b,--help) will show more help for each sub-command.";
    `S "BUGS";
    `P "Email bug reports to <mailto:sheets@alum.mit.edu>, or report them online at <https://github.com/dsheets/signpost/>."
  ] in
  Term.(pure serve $ sk $ pk $ resolv_ip $ zone $ client_pk),
  Term.info "spbased" ~version ~doc ~man

;;
Printexc.record_backtrace true;

match Term.eval default_cmd with
| `Error _ -> exit 1
| _ -> exit 0
