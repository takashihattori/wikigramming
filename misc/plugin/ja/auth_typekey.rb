# $Id: auth_typekey.rb,v 1.1 2005-03-06 09:05:23 fdiary Exp $
# Copyright (C) 2005 TAKEUCHI Hitoshi

def label_auth_typekey_login
<<EOS
<div class="hello">
  �ڡ������Խ�����ˤ�<a href="#{login_url}">������</a>��ɬ�פǤ���
</div>
EOS
end

def label_auth_typekey_hello
  '����ˤ��ϡ�%s����'
end

def label_auth_typekey_config
  'TypeKeyǧ��'
end

def label_auth_typekey_token
  'TypeKey�ȡ�����'
end

def label_auth_typekey_token_msg
  'TypeKey�Υȡ��������ꤷ�ޤ����ȡ������TypeKey�Υ����ȤΥ�������Ⱦ���ǳ�ǧ���Ƥ���������'
end
