open Lwt
open Dns
module Crypto = Sodium.Make(Sodium.Serialize.String)
module Ipv4 = Ipaddr.V4

module type ZONAL = sig
  module Key : sig
    type store
    type role
    type token

    val store : unit -> store
    val role : store -> string -> role
    val delegate : role -> string -> role
    val group : role list -> string -> role

    val token : store -> string -> string -> token
  end

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

  val ip : string -> ip
  val l : string -> label

  val zone : soa -> record list -> zone
  val soa_of_zone : zone -> soa
  val cond : cond -> record list -> record list -> record

  val domain : ?also:label list list -> ?rev:bool -> label list -> ip -> record
  val dynamic : Key.role -> label list -> record
  val tokenstore : label list -> Key.token list -> record

  val is_secret : unit -> cond
  val is_identified : Key.role -> cond
end

module Dns_curve = struct
  module Key = struct
    type store = unit
    type role = string
    type token = string * string

    let store () = ()
    let role store name = name
    let delegate role name = name
    let group rl name = name

    let token store name tok = (name,tok)
  end

  type ip = Ipv4.t
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
  type zone = { soa : soa; public : Loader.db; secret : Loader.db }

  let ip = Ipv4.of_string_exn
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
    let public = Loader.new_db () in
    let secret = Loader.new_db () in
    let load is_secret db =
      bind_soa soa soa.origin db;
      List.iter (fun addr -> Loader.add_a_rr addr soa.ttl master db)
        (snd soa.master_ns);
      List.iter (fun (ll,al) -> List.iter
        (fun addr -> Loader.add_a_rr addr soa.ttl (ll@soa.origin) db) al
      ) soa.other_ns;
      let rec eval = function
        | Mod dbfn -> dbfn soa db
        | Cond (Secret,rl,_) when is_secret -> List.iter eval rl
        | Cond (Secret,_,erl) when not is_secret -> List.iter eval erl
        | Cond (_,_,_) -> ()
      in List.iter eval rl
    in
    load false public;
    load true  secret;
    { soa; public; secret; }

  let soa_of_zone { soa } = soa
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

module Dns_curve_zonal : ZONAL = Dns_curve

module type ZONE = functor(Z : ZONAL) -> sig
  val zones : unit -> Z.zone list
end

type t = {
  addr : string;
  name : string list
}
module type DOMAIN = sig
  val zones : t list
end

module TestZone(Config : DOMAIN) : ZONE = functor (Zonal : ZONAL) -> struct
  open Zonal

  let keystore   = Key.store ()

  let sovereign  = Key.role keystore "sovereign"
  let root       = Key.delegate sovereign "root"
  let home       = Key.delegate root "home"
  let laptop     = Key.delegate root "laptop"
  let me         = Key.delegate root "me"
  let classified = Key.group [home; laptop; me] "classified"

  let secret = Key.token keystore "password" "pseudosecret"

  let zones () = List.map (fun {addr;name} ->
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
      dynamic home [l "home"];
    (*any [L "icann"; L "dns"] self;*)
      cond (is_secret ()) [
        dynamic laptop [l "laptop"];
        cond (is_identified classified) [
          tokenstore [l "tokens"] [secret];
        ] [];
      ] [];
    ]) Config.zones
end

module type NS = sig end

module Namespace(Zone : ZONE) : NS = struct

end

type sockaddr = Lwt_unix.sockaddr

module type DNS = sig
  val process : Dns.Loader.db ->
    src:sockaddr -> dst:sockaddr -> Packet.t -> Query.answer option Lwt.t

  module Processor : Dns_server.PROCESSOR
end

let nameserver_of_zone (pk,sk) (module Zone : ZONE) =
  let module Nameserver = struct
    module Z = Zone(Dns_curve)

    let zone = List.hd (Z.zones ())
    let pub = zone.Dns_curve.public
    let priv = zone.Dns_curve.secret

    let process db ~src ~dst packet =
      let open Packet in
      match packet.questions with
      | [] -> Log.questionless_query ~src ~dst packet; return None
      | [q] -> begin
        try
          let answer = Query.(answer q.q_name q.q_type db.Loader.trie) in
          return (Some answer)
        with exn ->
          print_endline (Printexc.to_string exn); exit 1
      end
      | _::_::_ -> Log.questionful_query ~src ~dst packet; return None

    module Processor =
      (val Dnscurve_processor.(
        split_of_process sk (process pub) (process priv)
       ))
  end in
  (module Nameserver : DNS)

let dns_port = 53

let keys = Crypto.box_keypair ()

let mydns = nameserver_of_zone keys (module TestZone(struct
  let zones = [
    { addr = "166.78.243.128"; name = ["domocracy"; "net"] };
  ]
end))

let serve sk pk resolv_ip zone =
  Lwt_main.run begin
    let address = "0.0.0.0" in
    let port = dns_port in
    let module MyDNS = (val mydns : DNS) in
    let processor = (module MyDNS.Processor : Dns_server.PROCESSOR) in
    Dns_server.serve_with_processor ~address ~port ~processor
  end
