open Lwt
module Crypto = Sodium.Make(Sodium.Serialize.String)

let fresh_keyf () = None, Crypto.box_keypair ()
let our_keyf sk pk () = None, (pk,sk)

let dns = Dns.Protocol.((module Client : CLIENT))

let serve sk pk server_pk domain =
  let config = `Static (["127.0.0.1",53],[]) in
  let client = Dnscurve_resolver.(
    between fresh_keyf (new_env ()) server_pk domain
      dns
      (Control_protocol.auth_client (our_keyf sk pk) server_pk dns)
  ) in

  let resolver_service = ref (Dns_resolver.create ~client ~config ()) in
  let reload_config config =
    resolver_service := Dns_resolver.create ~client ~config () in

  let dnsfn ~src ~dst packet =
    !resolver_service >>= fun resolver ->
    Dns_resolver.send_pkt resolver packet
    >>= fun packet ->
    Printf.printf "%s\n%!" (Dns.Packet.to_string packet);
    return (Some (Dns.Query.answer_of_response packet))
  in

  let processor =
    Dns_server.((processor_of_process dnsfn :> (module PROCESSOR))) in

  Lwt_main.run begin
    ignore (Lwt_unix.on_signal Sys.sighup (fun _ -> reload_config config));
    (* TODO: shed the privilege to bind a low port *)
    Dns_server.serve_with_processor ~address:"127.0.0.1" ~port:53 ~processor
  end
