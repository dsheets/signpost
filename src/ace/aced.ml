open Lwt
open Sodium
module IPv4 = Ipaddr.V4

let fresh_keyf () = None, Box.random_keypair ()

let dns = Dns.Protocol.((module Client : CLIENT))

let query_dns resolver _class _type _name =
  Dns_resolver_unix.resolve resolver _class _type _name
  >>= fun result ->
  return (Some (Dns.Query.answer_of_response result))

let serve sk pk server_pk domain =
  (* TODO: secure *)

  (* Get signpost servers using system resolver *)
  Dns_resolver_unix.create ()
  >>= fun sys_resolver ->
  let domain_string = Dns.Name.domain_name_to_string domain in
  Dns_resolver_unix.(gethostbyname sys_resolver domain_string)
  >>= fun signpost_base_ips ->
  let signpost_ns = (List.hd signpost_base_ips) in

  let config = `Static ([signpost_ns,53],[]) in
  let client = Dnscurve_resolver.(
    between fresh_keyf (new_env ()) server_pk domain
      dns
      (Control_protocol.auth_client None (sk,pk) server_pk dns)
  ) in

  let resolver_service = ref (Dns_resolver_unix.create ~client ~config ()) in
  let reload_config config =
    resolver_service := Dns_resolver_unix.create ~client ~config () in

  let dnsfn ~src ~dst packet =
    let open Dns.Packet in
    match packet.questions with 
    | [q] -> begin
		!resolver_service >>= fun resolver ->
		query_dns resolver q.q_class q.q_type q.q_name
             end
    | _ -> return_none
  in

  let processor =
    Dns_server.((processor_of_process dnsfn :> (module PROCESSOR))) in

  ignore (Lwt_unix.on_signal Sys.sighup (fun _ -> reload_config config));
  (* TODO: shed the privilege to bind a low port *)
  Dns_server_unix.serve_with_processor ~address:"127.0.0.1" ~port:53 ~processor
