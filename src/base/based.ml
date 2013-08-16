open Lwt
open Dns
module Crypto = Sodium.Make(Sodium.Serialize.String)
module IPv4 = Ipaddr.V4

module type INTERP = sig
  module Key : sig
    type role
    type token
    type store

    val new_store : unit -> store
    val role : string -> role
    val token : role -> string -> Sodium.public Sodium.Box.key -> token
    val store_token : store -> token -> store
    val get_token : store -> Sodium.public Sodium.Box.key -> token option
    val authenticate : role -> token -> bool
  end

  type security = Clear | Encrypted of Sodium.public Sodium.Box.key option

  type ip
  type label
  type cond
  type soa = {
    origin : label list;
    hostmaster : label list;
    master_ns : label list * ip list;
    other_ns : (label list * ip list) list;
    serial : int32;
    refresh : int32;
    retry : int32;
    expire : int32;
    min_ttl : int32;
    ttl : int32;
  }
  type record
  type zone
  type service = { zones : zone list; recursor : IPv4.t option }

  val ip : string -> ip
  val l : string -> label

  val zone : soa -> record list -> zone
  val cond : cond -> record list -> record list -> record

  val domain : ?also:label list list -> ?rev:bool -> label list -> ip -> record
  val dynamic : Key.role -> label list -> record
  val tokenstore : label list -> Key.token list -> record

  val is_secret : unit -> cond
  val is_identified : Key.role -> cond
end

module Dns_curve = struct
  module Key = struct
    type curve_pk = Sodium.public Sodium.Box.key
    module Store = Map.Make(struct
      type t = curve_pk
      let compare = Sodium.Box.compare_keys
    end)
    type role = string
    type token = role * string * curve_pk
    type store = token Store.t

    let new_store () = Store.empty
    let role name = name
    let token role name cred = (role, name, cred)
    let store_token store ((_,_,key) as tok) = Store.add key tok store
    let get_token store pk =
      try Some Store.(find pk store) with Not_found -> None
    let authenticate role (trole,_,_) = role = trole
  end

  type security = Clear | Encrypted of Key.curve_pk option
  let is_clear = function Clear -> true | Encrypted _ -> false

  type ip = IPv4.t
  type label = string
  type cond = Secret | Identified of Key.role
  type soa = {
    origin : label list;
    hostmaster : label list;
    master_ns : label list * ip list;
    other_ns : (label list * ip list) list;
    serial : int32;
    refresh : int32;
    retry : int32;
    expire : int32;
    min_ttl : int32;
    ttl : int32;
  }
  type record =
  | Mod of (soa -> Loader.db -> unit)
  | Cond of cond * record list * record list
  type zone = security -> Loader.db -> unit
  type service = { zones : zone list; recursor : IPv4.t option }

  let ip = IPv4.of_string_exn
  let l s = s

  let master_of_soa soa = (fst soa.master_ns)@soa.origin
  let bind_soa soa = Loader.add_soa_rr
    (master_of_soa soa)
    (soa.hostmaster @ soa.origin)
    soa.serial
    soa.refresh
    soa.retry
    soa.expire
    soa.min_ttl
    soa.ttl

  let zone soa rl =
    let master = master_of_soa soa in
    let load sec db =
      bind_soa soa soa.origin db;
      List.iter (fun addr -> Loader.add_a_rr addr soa.ttl master db)
        (snd soa.master_ns);
      List.iter (fun (ll,al) -> List.iter
        (fun addr -> Loader.add_a_rr addr soa.ttl (ll@soa.origin) db) al
      ) soa.other_ns;
      let rec eval = function
        | Mod dbfn -> dbfn soa db
        | Cond (Secret,rl,_) when not (is_clear sec) -> List.iter eval rl
        | Cond (Secret,_,erl) when is_clear sec -> List.iter eval erl
        | Cond (_,_,_) -> ()
      in List.iter eval rl
    in
    load

  let cond c rl erl = Cond (c,rl,erl)

  let domain ?(also=[]) ?(rev=false) ll addr =
    Mod (fun soa db ->
      let dom = ll @ soa.origin in
      Loader.add_a_rr addr soa.ttl dom db;
      if rev
      then begin
        let rev_name = Name.for_reverse addr in
        bind_soa soa rev_name db;
        Loader.add_ptr_rr dom soa.ttl rev_name db;
      end;
      List.iter (fun sub -> Loader.add_cname_rr dom soa.ttl (sub@dom) db) also
    )

  let dynamic role ll = Mod (fun _ _ -> ())

  let tokenstore ll tokl = Mod (fun _ _ -> ())

  let is_secret () = Secret
  let is_identified role = Identified role
end

module Dns_curve_interp : INTERP = Dns_curve

module type SIGNPOST = functor(I : INTERP) -> sig
  val dns : I.security -> I.service
end

type zone_binding = {
  addr : string;
  name : string list;
}
type services = {
  dns : string * Sodium.public Sodium.Box.key;
}
module type CONFIG = sig
  val zone_bindings : zone_binding list
  val services : services
end

module TestZone(Config : CONFIG) : SIGNPOST = functor (Interp : INTERP) -> struct
  open Interp

  let dns_ip,dns_pk = Config.services.dns

  let dns_user = Key.role "DNS User"
  let dns_tok = Key.token dns_user "DNS Tunnel" dns_pk
  let keystore = Key.store_token (Key.new_store ()) dns_tok

  let zones = List.map (fun {addr;name} ->
    let self = ip addr in
    let origin = List.map l name in

    let soa = {
      origin;
      hostmaster = [l "hostmaster"];
      master_ns = [l "ns1"], [self];
      other_ns = [];
      serial = 2013072200_l;
      refresh = 28800_l;
      retry = 7200_l;
      expire = 864000_l;
      min_ttl = 1_l;
      ttl = 1_l;
    } in
    zone soa [
      domain ~also:[[l "www"]] ~rev:true [] self;
    ]) Config.zone_bindings

  let dns = function
    | Clear ->
      { zones; recursor=None; }
    | Encrypted (Some pk) ->
      begin match Key.get_token keystore pk with
      | None -> { zones; recursor=None; }
      | Some tok ->
        if Key.authenticate dns_user tok
        then { zones; recursor=Some (IPv4.of_string_exn dns_ip); }
        else { zones; recursor=None; }
      end
    | Encrypted None -> { zones; recursor=None; }
end

module type NS = sig end

module Namespace(Signpost : SIGNPOST) : NS = struct

end

type sockaddr = Lwt_unix.sockaddr

module type DNS = sig
  val process : Dns.Loader.db -> recursor:IPv4.t option ->
    src:sockaddr -> dst:sockaddr -> Packet.t -> Query.answer option Lwt.t

  module Processor : Dns_server.PROCESSOR
end

let dns_port = 53

let nameserver_of_zone (pk,sk) (module Signpost : SIGNPOST) =
  let module Nameserver = struct
    module Z = Signpost(Dns_curve)

    let process db ~recursor ~src ~dst packet =
      let open Packet in
      match packet.questions with
      | [] -> Log.questionless_query ~src ~dst packet; return None
      | [q] -> begin
        try
          let answer = Query.(answer q.q_name q.q_type db.Loader.trie) in
          match recursor, answer.Query.rcode with
          | None, _ | _, Packet.NoError -> return (Some answer)
          | Some recursor_ip, _ ->
            Dns_resolver.create
              ~client:(module Dns.Protocol.Client)
              ~config:(`Static ([IPv4.to_string recursor_ip, dns_port],[])) ()
            >>= fun resolver ->
            Dns_resolver.send_pkt resolver packet
            >>= fun packet ->
            return (Some (Dns.Query.answer_of_response packet))
        with exn ->
          print_endline (Printexc.to_string exn); exit 1
      end
      | _::_::_ -> Log.questionful_query ~src ~dst packet; return None

    let process_of_security sec =
      let { Dns_curve.zones; recursor } = Z.dns sec in
      let db = Loader.new_db () in
      List.iter (fun zonef -> zonef sec db) zones;
      process db ~recursor

    module Processor =
      (val Control_protocol.(
        auth_server sk Dns.Protocol.((module Server : SERVER))
          Dns_server.((processor_of_process
                         (process_of_security Dns_curve.Clear)
                       :> (module PROCESSOR)))
          Dns_server.((processor_of_process
                         (process_of_security (Dns_curve.Encrypted None))
                       :> (module PROCESSOR)))
          (Dnscurve_processor.of_process (fun chan ->
            (* TODO: memoize authenticated databases *)
            process_of_security
              (Dns_curve.Encrypted (Some chan.Dnscurve.client_pk))
           ))
       ))
  end in
  (module Nameserver : DNS)

let mydns server_keys addr name client_pk = nameserver_of_zone server_keys
  (module TestZone(struct
    let zone_bindings = [ { addr; name }; ]
    let services = { dns = ("8.8.8.8", client_pk) }
  end))

let serve sk pk resolv_ip zone client_pk =
  Lwt_main.run begin
    let address = "0.0.0.0" in
    let port = dns_port in
    let module MyDNS = (val mydns (pk,sk) resolv_ip zone client_pk : DNS) in
    let processor = (module MyDNS.Processor : Dns_server.PROCESSOR) in
    Dns_server.serve_with_processor ~address ~port ~processor
  end
