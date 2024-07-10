# $Id: en.rb,v 1.20 2008-08-07 09:54:21 hiraku Exp $
# en.rb
#
# Copyright (C) 2003 Masao Mutoh <mutoh@highway.ne.jp>
# You can redistribute it and/or modify it under the terms of
# the Ruby's licence.
#
# Original file is ja.rb:
# Copyright (C) 2002-2003 TAKEUCHI Hitoshi <hitoshi@namaraii.com>
# You can redistribute it and/or modify it under the terms of
# the Ruby's licence.
#
module Hiki
  module Messages_en
    def msg_recent; 'Recent' end
    def msg_evalsubmit; 'Eval' end
    def msg_create; 'Create' end
    def msg_view; 'View' end
    def msg_apply; 'Apply' end
    def msg_diff; 'Diff' end
    def msg_edit; 'Edit' end
    def msg_search; 'Search' end
    def msg_admin; 'Admin' end
    def msg_login; 'Login' end
    def msg_logout; 'Logout' end
    def msg_search_name; 'Search by a function name' end
    def msg_search_spec; 'Search by a specification' end
    def msg_search_result; 'Search Results' end
    def msg_search_hits; '%2$d function(s) hit for the query \'%1$s\'' end
    def msg_search_not_found; 'No functions for the query \'%s\' were found.' end
    def msg_frontpage; 'Top' end
    def msg_hitory; 'History' end
    def msg_index; 'Index' end
    def msg_recent_changes; 'Changes' end
    def msg_newpage; 'New' end
    def msg_no_recent; '<P>There is no data.</P>' end
    def msg_thanks; 'Thank you for your update.' end
    def msg_save_conflict; 'There is a conflict with your updates.  Copy the content below to a text editor and edit the page after referring to the latest version.' end
    def msg_time_format; "%Y-%m-%d #DAY# %H:%M:%S" end
    def msg_date_format; "%Y-%m-%d " end
    def msg_day; %w(Sun Mon Tue Wed Thr Fri Sat) end
    def msg_preview; 'Confirm the content below.  If there are no problems, save it with the save button. -&gt;<a href="#form">Form</a>' end
    def msg_mail_on; 'Send update e-mails' end
    def msg_mail_off; 'Do not send update e-mails' end
    def msg_use; 'Use' end
    def msg_unuse; 'Don\'t use' end
    def msg_login_info; 'If you want to login as an administrator, type \'admin\' in the Name field.' end
    def msg_login_failure; 'Wrong name or password.' end
    def msg_name; 'Name' end
    def msg_password; 'Password' end
    def msg_ok; 'OK' end
    def msg_invalid_password; 'Your password is not correct.  Your changes have not yet been saved.' end
    def msg_save_config; 'Your configuration changes have been saved.' end
    def msg_freeze; 'This page is frozen.  You will need an admin password to change this page.' end
    def msg_freeze_mark; '[Frozen]' end
    def msg_already_exist; 'That page already exists.' end
    def msg_page_not_exist; 'This page does not exist.  Feel free to create it yourself :-)' end
    def msg_invalid_filename(s); "The page name contains an invalid character or is over the maximum length of #{s} bytes.  Please fix the page name." end
    def msg_delete; 'Deleted' end
    def msg_delete_page; 'The page has been deleted.' end
    def msg_follow_link; 'Click the following link to view your page: ' end
    def msg_match_title; '(matched in title)' end
    def msg_match_keyword; '(matched in keyword)' end
    def msg_duplicate_page_title; 'That page title already exists.' end
    def msg_missing_anchor_title; 'Create and edit the page %s.' end
    def msg_unbalanced_paren; 'Unbalanced parentheses.' end
    # (config)
    def msg_config; 'Hiki Configuration'; end
    # (diff)
    def msg_diff_add; 'Added parts are displayed <ins class="added">like this</ins>.'; end
    def msg_diff_del; 'Deleted parts are displayed <del class="deleted">like this</del>.'; end
    # (edit)
    def msg_description; 'Description'; end
    def msg_funcname; 'Function name'; end
    def msg_funcarg; 'Argument(s)'; end
    def msg_funcbody; 'Function body'; end
    def msg_require_test; 'Required function(s) and Test case(s)'; end
    def msg_freeze_checkbox; 'Freeze the current page.'; end
    def msg_preview_button; 'Preview'; end
    def msg_require_button; 'Require'; end
    def msg_save; 'Save'; end
    def msg_cancel; 'Cancel'; end
    def msg_update_timestamp; 'Update timestamp'; end
    def msg_latest; 'Latest version'; end
    def msg_rules; %Q|See <a href="#{@cgi_name}?TextFormattingRules">TextFormattingRules</a> for formatting help.|; end
    # (view)
    def msg_last_modified; 'Last modified'; end
    def msg_keyword; 'Keyword(s)'; end
    def msg_reference; 'References'; end
    def msg_input_is_spam; 'Input is treated as SPAM.'; end
    # (apply)
    def msg_modified_newer; 'Functions modified newer than %s:'; end
  end
end
