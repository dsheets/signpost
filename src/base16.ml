
module To_string = struct
  let h = "0123456789abcdef"

  let t ins =
    let len = (String.length ins) * 2 in
    let s = String.create len in
    for i=0 to len - 1 do
      let c = 0xf land ((int_of_char ins.[i/2]) lsr (4 * (1 - (i mod 2)))) in
      s.[i] <- h.[c]
    done;
    s

  let string ins =
    let len = (String.length ins) / 2 in
    let s = String.create len in
    for i=0 to len - 1 do
      s.[i] <- Scanf.sscanf (String.sub ins (i*2) 2) "%x" (Char.chr);
    done;
    s
end
