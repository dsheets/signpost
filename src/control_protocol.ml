open Dns.Protocol
open Dnscurve

let auth_client keyring ident server_pk inside =
  let open Dnscurve_resolver in
  let module I = (val streamlined server_pk inside : DNSCURVECLIENT) in
  let module Client = struct
    include I

    let marshal ?alloc = I.marshal ?alloc keyring ident
  end in
  (module Client : CLIENT)

let auth_server sk outside clear_proc unauth_proc auth_proc =
  let open Dnscurve_processor in
  fallback_dns clear_proc
    sk outside
    (fallback_curve unauth_proc
       sk outside auth_proc)
