# -*- coding: euc-jp -*-
# $Id: ja.rb,v 1.15 2008-02-12 15:06:08 hiraku Exp $
# Copyright (C) 2002-2003 TAKEUCHI Hitoshi <hitoshi@namaraii.com>
# You can redistribute it and/or modify it under the terms of
# the Ruby's licence.
module Hiki
  module Messages_ja
    def msg_recent; '��������' end
    def msg_evalsubmit; '�¹�' end
    def msg_create; '��������' end
    def msg_view; 'ɽ��' end
    def msg_apply; 'Apply' end
    def msg_diff; '��ʬ' end
    def msg_edit; '�Խ�' end
    def msg_search; '����' end
    def msg_admin; '����' end
    def msg_login; '������' end
    def msg_logout; '��������' end
    def msg_search_name; '�ؿ�̾�ˤ�븡��' end
    def msg_search_spec; '���ͤˤ�븡��' end
    def msg_search_result; '�������' end
    def msg_search_hits; '\'%s\'�˳�������ؿ���%d�ĸ��Ĥ���ޤ�����' end
    def msg_search_not_found; '\'%s\'�˳�������ؿ��ϸ��Ĥ���ޤ���Ǥ�����' end
    def msg_frontpage; '�ȥå�' end
    def msg_hitory; '��������' end
    def msg_index; '�ڡ�������' end
    def msg_recent_changes; '��������' end
    def msg_newpage; '����' end
    def msg_no_recent; '<P>��������¸�ߤ��ޤ���</P>' end
    def msg_thanks; '�������꤬�Ȥ��������ޤ�����' end
    def msg_save_conflict; '���������ͤ��ޤ��������������Ƥ�ƥ����ȥ��ǥ����ʤɤ���¸�����ǿ��Υڡ����򻲾ȸ�˺��Խ����Ƥ���������' end
    def msg_time_format; "%Y-%m-%d #DAY# %H:%M:%S" end
    def msg_date_format; "%Y-%m-%d " end
    def msg_day; %w(�� �� �� �� �� �� ��) end
    def msg_preview; '�ʲ��Υץ�ӥ塼���ǧ�������꤬�ʤ���Хڡ����β��ˤ�����¸�ܥ������¸���Ƥ������� ��<a href="#form">�Խ��ե�����</a>' end
    def msg_mail_on; '�᡼�������' end
    def msg_mail_off; '������' end
    def msg_use; '���Ѥ���' end
    def msg_unuse; '���Ѥ��ʤ�' end
    def msg_login_info; '�����ԤȤ��ƥ����󤹤�ݤϡ��桼��̾�� admin �����Ϥ��Ƥ���������' end
    def msg_login_failure; '�桼��̾�ޤ��ϥѥ���ɤ��ְ�äƤ��ޤ���' end
    def msg_name; '�桼��̾' end
    def msg_password; '�ѥ����' end
    def msg_ok; 'OK' end
    def msg_invalid_password; '�ѥ���ɤ��ְ�äƤ��ޤ����ޤ�����������¸����Ƥ��ޤ���' end
    def msg_save_config; '�������¸���ޤ�����' end
    def msg_freeze; '���Υڡ�������뤵��Ƥ��ޤ�����¸�ˤϴ������ѤΥѥ���ɤ�ɬ�פǤ���' end
    def msg_freeze_mark; '������' end
    def msg_already_exist; '����Υڡ����Ϥ��Ǥ�¸�ߤ��Ƥ��ޤ���' end
    def msg_page_not_exist; '����Υڡ�����¸�ߤ��ޤ��󡣤��ҡ��������Ƥ�������:-)' end
    def msg_invalid_filename(s); "������ʸ�����ޤޤ�Ƥ��뤫������Ĺ(#{s}�Х���)��Ķ���Ƥ��ޤ����ڡ���̾�������Ƥ���������" end
    def msg_delete; '�ڡ����������ޤ���' end
    def msg_delete_page; '�ʲ��Υڡ����������ޤ�����' end
    def msg_follow_link; '�ʲ��Υ�󥯤򤿤ɤäƤ�������: ' end
    def msg_match_title; '[�����ȥ�˰���]' end
    def msg_match_keyword; '[������ɤ˰���]' end
    def msg_duplicate_page_title; '���ꤷ�������ȥ�ϴ���¸�ߤ��Ƥ��ޤ���' end
    def msg_missing_anchor_title; '�ڡ��� %s �򿷵����������Խ����ޤ���' end
    def msg_unbalanced_paren; '��̤ο�����äƤ��ޤ���.' end
    # (config)
    def msg_config; 'Hiki �Ķ�����'; end
    # (diff)
    def msg_diff_add; '�Ǹ�ι������ɲä��줿��ʬ��<ins class="added">���Τ褦��</ins>ɽ�����ޤ���'; end
    def msg_diff_del; '�Ǹ�ι����Ǻ�����줿��ʬ��<del class="deleted">���Τ褦��</del>ɽ�����ޤ���'; end
    # (edit)
    def msg_description; '����'; end
    def msg_funcname; '�ؿ�̾'; end
    def msg_funcarg; '����̾'; end
    def msg_funcbody; '�ؿ�����'; end
    def msg_require_test; 'ɬ�פʴؿ��ȥƥ��ȥ�����'; end
    def msg_freeze_checkbox; '�ڡ��������'; end
    def msg_preview_button; '�ץ�ӥ塼'; end
    def msg_require_button; 'Require'; end
    def msg_save; '��¸'; end
    def msg_cancel; '����󥻥�'; end
    def msg_update_timestamp; '�����ॹ����פ򹹿�����'; end
    def msg_latest; '�ǿ��Ǥ򻲾�'; end
    def msg_rules; %Q|�������狼��ʤ�����<a href="#{@cgi_name}?TextFormattingRules">TextFormattingRules</a>�򻲾Ȥ��Ƥ���������|; end
    # (view)
    def msg_last_modified; '��������'; end
    def msg_keyword; '�������'; end
    def msg_reference; '����'; end
    def msg_input_is_spam; '���Ϥ��줿�ǡ����򥹥ѥ��Ƚ�ꤷ�ޤ�����'; end
    # (apply)
    def msg_modified_newer; '%s������ѹ����줿�ؿ�:'; end
  end
end
