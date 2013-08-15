open Dns.Protocol
open Dnscurve

let auth_client keyf server_pk inside =
  let keyring, ident = keyf () in
  let open Dns_resolver in
  let module I = (val inside : CLIENT) in
  let module Client = struct
    include I

    let marshal pkt =
      List.rev_map (fun (ictxt,b) ->
        let _chan, buf = encode_streamlined_query ?keyring ident server_pk b in
        ictxt, buf
      ) (I.marshal pkt)

  end in
  (module Client : CLIENT)

let auth_server sk outside clear_proc unauth_proc auth_proc =
  let open Dnscurve_processor in
  fallback_dns clear_proc
    sk outside
    (fallback_curve unauth_proc
       sk outside auth_proc)
