--- ./js-utils/gen_install.ml
+++ ./js-utils/gen_install.ml
@@ -30,11 +30,30 @@
   lines_of_file "setup.data"
   |> List.map (fun line -> Scanf.sscanf line "%[^=]=%S" (fun k v -> (k, v)))
 
+let slashify s =
+  let l = String.length s in
+  let b = Bytes.create l in
+  for i = 0 to l - 1 do
+    let c = s.[i] in
+    Bytes.set b i (if c = '\\' then '/' else c)
+  done;
+  if l > 1 && s.[1] = ':' && (s.[0] >= 'a' && s.[0] <= 'z') &&
+     (l = 2 || Bytes.get b 1 = '/' ) then (
+    Bytes.set b 1 (Char.uppercase s.[0])
+  );
+  Bytes.unsafe_to_string b
+
+let slashify =
+  match Sys.os_type with
+  | "Win32" -> slashify
+  | _ -> fun id -> id
+
 let remove_cwd =
-  let prefix = Sys.getcwd () ^ Filename.dir_sep in
+  let prefix = slashify (Sys.getcwd () ^ Filename.dir_sep) in
   let len_prefix = String.length prefix in
   fun fn ->
     let len = String.length fn in
+    let fn = slashify fn in
     if len >= len_prefix && String.sub fn 0 len_prefix = prefix then
       String.sub fn len_prefix (len - len_prefix)
     else
