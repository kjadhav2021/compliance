# @summary This function construct standard policy title
#
# @example
#   function compliance::policy_title(::policy_title('x_1', 'Ensure patching updated' )
#
function compliance::policy_title(
  String            $item_id           = '',
  String            $item_title        = '',
  Optional[String]  $item_setting      = '',
  Optional[String]  $item_param        = '',
) {
  "(${item_id}) ${item_title} ~:${item_setting}**${item_param}"
}
