
module Make(S: Network_stack.S) : Active_list.Instance
  with type context = S.t
