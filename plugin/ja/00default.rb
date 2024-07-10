#
# preferences (resources)
#
add_conf_proc( 'default', '����' ) do
  saveconf_default
  <<-HTML
      <h3 class="subtitle">������̾</h3>
      <p>������̾����ꤷ�ޤ���</p>
      <p><input name="site_name" value="#{CGI::escapeHTML(@conf.site_name)}" size="40"></p>
      <h3 class="subtitle">����̾</h3>
      <p>���ʤ���̾������ꤷ�ޤ���</p>
      <p><input name="author_name" value="#{CGI::escapeHTML(@conf.author_name)}" size="40"></p>
      <h3 class="subtitle">�᡼�륢�ɥ쥹</h3>
      <p>���ʤ��Υ᡼�륢�ɥ쥹����ꤷ�ޤ���1�Ԥ�1���ɥ쥹���Ļ��ꤷ�ޤ���</p>
      <p><textarea name="mail" rows="4" cols="50">#{CGI::escapeHTML(@conf.mail.join("\n"))}</textarea></p>
      <h3 class="subtitle">������᡼�������</h3>
      <p>�ڡ����ι��������ä����˥᡼������Τ��뤫�ɤ�������ꤷ�ޤ����᡼��ϴ�������ǻ��ꤷ�����ɥ쥹����������ޤ������餫����hikiconf.rb��SMTP�����Ф����ꤷ�Ƥ����Ƥ���������</p>
      <p><select name="mail_on_update">
         <option value="true"#{@conf.mail_on_update ? ' selected' : ''}>�᡼�� ������</option>
         <option value="false"#{@conf.mail_on_update ? '' : ' selected'}>������</option>
         </select></p>
  HTML
end

add_conf_proc( 'password', '�ѥ����' ) do
  '<h3 class="password">�ѥ����</h3>' +
    case saveconf_password
    when :password_change_success
      '<p>�������ѥѥ���ɤ��ѹ����ޤ�����</p>'
    when :password_change_failure
      '<p>�������ѥѥ���ɤ��ְ�äƤ��뤫���ѥ���ɤ����פ��ޤ���</p>'
    when nil
      '<p>�������ѥѥ���ɤ��ѹ����ޤ���</p>'
    end +
    <<-HTML
        <p>���ߤΥѥ����: <input type="password" name="old_password" size="40"></p>
        <p>�������ѥ����: <input type="password" name="password1" size="40"></p>
        <p>�������ѥ���ɡʳ�ǧ�Ѥ˺����Ϥ��Ƥ���������: <input type="password" name="password2" size="40"></p>
    HTML
end

add_conf_proc( 'theme', 'ɽ������' ) do
  saveconf_theme
  r = <<-HTML
      <h3 class="subtitle">�ơ��ޤλ���</h3>
      <p>ɽ���˻��Ѥ���ơ��ޤ����򤹤뤳�Ȥ��Ǥ��ޤ���</p>
      <p><select name="theme">
  HTML
  @conf_theme_list.each do |theme|
    r << %Q|<option value="#{theme[0]}"#{if theme[0] == @conf.theme then " selected" end}>#{theme[1]}</option>|
  end
  r << <<-HTML
      </select></p>
      <h3 class="subtitle">�ơ���URL�λ���</h3>
      <p>�ơ��ޤ�����URL����ꤹ�뤳�Ȥ��Ǥ��ޤ���ľ��CSS����ꤷ����硢��Ρ֥ơ��ޤλ���פ����򤷤��ơ��ޤ�̵�뤵�졢���ꤷ��CSS���Ȥ��ޤ���</p>
      <p><input name="theme_url" value="#{CGI::escapeHTML(@conf.theme_url)}" size="60"></p>
      <h3 class="subtitle">�ơ��ޥǥ��쥯�ȥ�λ���</h3>
      <p>�ơ��ޤ�����ǥ��쥯�ȥ����ꤹ�뤳�Ȥ��Ǥ��ޤ�����ʣ�����ֻ��˻��ѡ�</p>
      <p><input name="theme_path" value="#{CGI::escapeHTML(@conf.theme_path)}" size="60"></p>
      <h3 class="subtitle">�����ɥС�������</h3>
      <p>�ơ��ޤˤ�äƤϥ����ɥС������Ѥ����ɽ���������Τ�����ޤ������ξ�硢�����ɥС���ɽ���򥪥դˤ��뤳�Ȥ��Ǥ��ޤ���</p>
      <p><select name="sidebar">
         <option value="true"#{@conf.use_sidebar ? ' selected' : ''}>���Ѥ���</option>
         <option value="false"#{@conf.use_sidebar ? '' : ' selected'}>���Ѥ��ʤ�</option>
         </select></p>
      <h3 class="subtitle">�ᥤ�󥨥ꥢ�Υ��饹̾(CSS)�λ���</h3>
      <p>�ǥե���ȤǤ���ʸ��ʬ�Υ��饹̾�Ȥ���'main'����Ѥ��ޤ���������ʳ��Υ��饹̾����Ѥ��������˻��ꤷ�ޤ���</p>
      <p><input name="main_class" value="#{CGI::escapeHTML(@conf.main_class)}" size="20"></p>
      <h3 class="subtitle">�����ɥС��Υ��饹̾(CSS)�λ���</h3>
      <p>�ǥե���ȤǤϥ����ɥС��Υ��饹̾�Ȥ���'sidebar'����Ѥ��ޤ���������ʳ��Υ��饹̾����Ѥ��������˻��ꤷ�ޤ���</p>
      <p><input name="sidebar_class" value="#{CGI::escapeHTML(@conf.sidebar_class)}" size="20"></p>
      <h3 class="subtitle">�����ȥ�󥯤�����</h3>
      <p>��¸�Υڡ����˼�ưŪ�˥�󥯤����ꤹ�륪���ȥ�󥯵�ǽ����Ѥ��뤫�ɤ������ꤷ�ޤ���</p>
      <p><select name="auto_link">
         <option value="true"#{@conf.auto_link ? ' selected' : ''}>���Ѥ���</option>
         <option value="false"#{@conf.auto_link ? '' : ' selected'}>���Ѥ��ʤ�</option>
         </select></p>
      <h3 class="subtitle">WikiName �ˤ���󥯵�ǽ������</h3>
      <p>WikiName �ˤ���󥯵�ǽ����Ѥ��뤫�ɤ������ꤷ�ޤ���</p>
      <p><select name="use_wikiname">
         <option value="true"#{@conf.use_wikiname ? ' selected' : ''}>���Ѥ���</option>
         <option value="false"#{@conf.use_wikiname ? '' : ' selected'}>���Ѥ��ʤ�</option>
         </select></p>
  HTML
end

add_conf_proc( 'xmlrpc', 'XML-RPC' ) do
  saveconf_xmlrpc

  <<-HTML
      <h3 class="subtitle">XML-RPC</h3>
      <p>XML-RPC ���󥿥ե�������ͭ���ˤ��뤫�ɤ�������ꤷ�ޤ���</p>
      <p><select name="xmlrpc_enabled">
         <option value="true"#{@conf.xmlrpc_enabled ? ' selected' : ''}>ͭ��</option>
         <option value="false"#{@conf.xmlrpc_enabled ? '' : ' selected'}>̵��</option>
         </select></p>
  HTML
end

