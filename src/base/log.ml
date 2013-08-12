open Printf

let questionless_query ~src ~dst packet =
  eprintf "Ya query! It ain't got no questions innit!\n"

let questionful_query ~src ~dst packet =
  eprintf "Ya query! It got too many questions innit!\n"
