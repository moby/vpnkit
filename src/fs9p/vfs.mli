(** Virtual filesystem.

    A virtual filesystem is an abstract description of {{!File}files},
    {{!Dir}directoires}, {{!Inode}inodes} and {{!Error}error codes}.
*)

open Astring
open Result

(** Error codes. *)
module Error : sig
  type err = { errno : int32 option; descr : string }
  (** The type for generic errors. *)

  (** The type for FS errors. *)
  type t =
    | Noent  (** No such file or directory. *)
    | Isdir  (** The entry is a directory. *)
    | Notdir  (** The entry is not a directory. *)
    | Read_only_file  (** The file is read-only. *)
    | Perm  (** The operation is not permitted. *)
    | Other of err  (** Generic error function. *)

  (** Infix operators. *)
  module Infix : sig
    val ( >>*= ) :
      ('a, t) result Lwt.t ->
      ('a -> ('b, t) result Lwt.t) ->
      ('b, t) result Lwt.t
  end

  val no_entry : ('a, t) result
  (** [no_entry] is [Error Noent]. *)

  val is_dir : ('a, t) result
  (** [is_dir] is [Error Isdir]. *)

  val not_dir : ('a, t) result
  (** [not_dir] is [Error Notdir]. *)

  val read_only_file : ('a, t) result
  (** [read_only_file] is [Error Read_only_file]. *)

  val perm : ('a, t) result
  (** [perm] is [Error Perm]. *)

  val other : ?errno:int32 -> ('a, unit, string, ('b, t) result) format4 -> 'a
  (** [Other ~errno descr] is [Error { errno; descr }]. [errno] is 0
      if not set. *)

  val negative_offset : int64 -> ('a, t) result
  (** [negative_offset o] is an error saying that [o] is negative. *)

  val offset_too_large : offset:int64 -> int64 -> ('a, t) result
  (** [offset_too_large ~offset len] is an error saying that [offset]
      is beyond the end of the file ([len]). *)

  val pp : t Fmt.t
end

type 'a or_err = ('a, Error.t) Result.result Lwt.t
(** The type of errors. *)

val ok : 'a -> 'a or_err
(** [ok x] is [Lwt.return (Ok x)] *)

val error : ('a, unit, string, 'b or_err) format4 -> 'a
(** [error fmt] is [Lwt.return (Error <fmt>)]. *)

type perm = [ `Normal | `Exec | `Link of string ]

type metadata = { length : int64; perm : perm }

(** File operations. *)
module File : sig
  type fd
  (** The type for open files, e.g. file descriptors. *)

  val create_fd :
    read:(offset:int64 -> count:int -> Cstruct.t or_err) ->
    write:(offset:int64 -> Cstruct.t -> unit or_err) ->
    fd
  (** Create an open file object. *)

  val read : fd -> offset:int64 -> count:int -> Cstruct.t or_err
  (** [read f ~offset ~count] reads an open file. *)

  val write : fd -> offset:int64 -> Cstruct.t -> unit or_err
  (** [write f ~offset] writes in a open file. *)

  type t
  (** The type for files. *)

  val pp : t Fmt.t
  (** [pp] is the pretty-printer for files. *)

  val create :
    stat:(unit -> metadata or_err) ->
    open_:(unit -> fd or_err) ->
    remove:(unit -> unit or_err) ->
    truncate:(int64 -> unit or_err) ->
    chmod:(perm -> unit or_err) ->
    t
  (** [create] is the file [t] such that FIXME. *)

  val stat : t -> metadata or_err
  (** [stat t] is [t]'s metadata. *)

  val size : t -> int64 or_err
  (** [size t] is [t]'s size. *)

  val open_ : t -> fd or_err
  (** [open_ t] if a file-descriptor for [t]. *)

  val remove : t -> unit or_err
  (** [remove t] removes [t]. *)

  val truncate : t -> int64 -> unit or_err
  (** [truncate t len] sets the length of [t] to [len].  If the new
       length is shorter, the file is truncated.  If longer, it is
       padded with zeroes. *)

  val chmod : t -> perm -> unit or_err
  (** [chmod t mode] changes the mode of [t]. *)

  (** {1 Basic constructors} *)

  val ro_of_string : ?perm:perm -> string -> t
  (** [ro_of_string s] is the static file containing [s]. *)

  val rw_of_string : string -> t * (unit -> string)
  (** [rw_of_string init] is a mutable file that initially contains
        [init] and a function which can be called to get the current
        contents. *)

  val status : ?length:(unit -> int Lwt.t) -> (unit -> string Lwt.t) -> t
  (** [status f] is the file containing the result of [f]. [f] is
      evaluated everytime the file is open. If [length] is not set,
      [f] will also be called during [stat] queries.*)

  val command : ?init:string -> (string -> string or_err) -> t
  (** [command ?init f] is the file containing the result of [f]. [f]
      is evaluated on every write, with the contents of the file as
      argument. Initially the file contains [init]. *)

  (** {1 K/V stores.} *)

  val of_kv :
    read:(unit -> Cstruct.t option or_err) ->
    write:(Cstruct.t -> unit or_err) ->
    stat:(unit -> metadata or_err) ->
    remove:(unit -> unit or_err) ->
    chmod:(perm -> unit or_err) ->
    t
  (** [of_kv ~read ~write ~remove ~stat] interprets values from a k/v
      store as files. Handles reading and writing regions of the
      file. *)

  val of_kvro :
    read:(unit -> Cstruct.t option or_err) ->
    stat:(unit -> metadata or_err) ->
    t
  (** [of_kvro] is similar to {!of_kv} but for read-only
      values. *)

  val stat_of :
    read:(unit -> Cstruct.t option or_err) -> unit -> metadata or_err
  (** [stat_of ~read] makes a [stat] function from [read].  The
      function reads the file to get the length, and reports the type
      as [`Normal]. *)

  (** {1 Streams} *)

  module Stream : sig
    type t
    (** The type of typed streams.  *)

    type 'a session
    (** The type for stream sessions. *)

    val session : 'a -> 'a session
    (** [session init] creates a fresh session, whose initial value is
        [init].  *)

    val publish : 'a session -> 'a -> unit
    (** [publish s v] publishes [v] in the session [s]. *)

    val create : 'a Fmt.t -> 'a session -> t
    (** [create pp session] is a fresh file stream. Readers of the
        stream will first get an initial line, printed with [pp],
        corresponding to the current session's value. Everytime the
        session's state is changing, a new line -- formatted with [pp]
        -- is broadcasted to all the current readers of the stream. *)
  end

  val of_stream : (unit -> Stream.t Lwt.t) -> t
  (** [of_stream s] is the file which will be, once opened, similar to
    the stream [s ()]. *)

  (** {1 Errors} *)

  val err_no_entry : 'a or_err

  val err_read_only : 'a or_err
end

(** Directory operations. *)
module rec Dir : sig
  type t
  (** The type for directories. *)

  val pp : t Fmt.t
  (** [pp] is a pretty-printer for directories. *)

  val ls : t -> Inode.t list or_err
  (** The [ls] commands. *)

  val mkfile : t -> ?perm:perm -> string -> Inode.t or_err
  (** The [mkfile] command. *)

  val lookup : t -> string -> Inode.t or_err
  (** The [lookup] command. *)

  val mkdir : t -> string -> Inode.t or_err
  (** The [mkdir] command. *)

  val remove : t -> unit or_err
  (** The [remove] command. FIXME: shouldn't it be string -> unit? *)

  val rename : t -> Inode.t -> string -> unit or_err
  (** The [rename] command. *)

  val empty : t
  (** [empty] is the empty directory. *)

  val of_list : (unit -> Inode.t list or_err) -> t
  (** [of_list l] is a read-only, static directory containing only the
      inodes [l]. The sub-directories are re-evaluated on every [ls]
      and [read]. *)

  val of_map_ref : Inode.t String.Map.t ref -> t
  (** [of_map_ref m] is a read-only directory containing the inodes
      defined in [m]. The content of the directory is computed
      dynamically by accessing elements in the map on every access. *)

  val read_only :
    ls:(unit -> Inode.t list or_err) ->
    lookup:(string -> Inode.t or_err) ->
    remove:(unit -> unit or_err) ->
    t
  (** [read_only] is a read-only directory. FIXME. *)

  val dir_only :
    ls:(unit -> Inode.t list or_err) ->
    lookup:(string -> Inode.t or_err) ->
    mkdir:(string -> Inode.t or_err) ->
    remove:(unit -> unit or_err) ->
    rename:(Inode.t -> string -> unit or_err) ->
    t
  (** [dir_only] is a directory which contains only
      directories. FIXME. *)

  val create :
    ls:(unit -> Inode.t list or_err) ->
    mkfile:(string -> perm -> Inode.t or_err) ->
    lookup:(string -> Inode.t or_err) ->
    mkdir:(string -> Inode.t or_err) ->
    remove:(unit -> unit or_err) ->
    rename:(Inode.t -> string -> unit or_err) ->
    t
  (** [creae] is a generic directory. *)

  val err_read_only : 'a or_err
  (** {1 Errors} *)

  val err_already_exists : 'a or_err

  val err_dir_only : 'a or_err

  val err_no_entry : 'a or_err
end

and Inode : sig
  (** Inode.t operations. *)

  type t
  (** The type for inodes. *)

  val pp : t Fmt.t
  (** [pp] is the pretty-printer for inodes. *)

  type kind = [ `File of File.t | `Dir of Dir.t ]
  (** The type for inode kinds. *)

  val file : string -> File.t -> t
  (** [file name f] is the inode [t] such that [basename t] is [name]
      and [kind t] is [File f]. *)

  val dir : string -> Dir.t -> t
  (** [dir name d] is the inode [t] such that [basename t] is [name]
      and [kind t] is [Dir d]. *)

  val basename : t -> string
  (** [basenane t] is [t]'s basename. *)

  val set_basename : t -> string -> unit
  (** [set_basename t name] changes [t]'s basename to [name]. *)

  val kind : t -> kind
  (** [kind t] is [t]'s kind. *)

  val ino : t -> int64
  (** [ino t] is a unique "inode number" for the file. If two files have the
      same inode number, then they are the same file. *)
end

module Logs : sig
  val dir : Dir.t
  (** [dir] is a projection of [Logs.Src] into the VFS: each entry [s] in
      [Logs.Src.list ()] has a subdirectory [<fs>/src/<s>] containing
      two files:

      {ul
      {- [<fs>/src/<s>/doc] is [Logs.Src.doc s]. The file is read-only. }
      {- [<fs>/src/<s>/level] is [Logs.Src.level s]. Changing the contents
         of that file will trigger {!Logs.Src.set_level}. }}
  *)
end
