# -*- coding: euc-jp -*-
#
# Japanese resource of amazon plugin
#
# Copyright (C) 2002 HAL99 <hal99@mtj.biglobe.ne.jp>
# You can redistribute it and/or modify it under GPL2.
#

#
# isbn_image_left: ���ꤷ��ISBN�ν�Ƥ�class="left"��ɽ��
#   �ѥ�᥿:
#     asin:    ASIN�ޤ���ISBN(ɬ��)
#     comment: ������(��ά��)
#
# isbn_image_right: ���ꤷ��ISBN�ν�Ƥ�class="right"��ɽ��
#   �ѥ�᥿:
#     asin:    ASIN�ޤ���ISBN(ɬ��)
#     comment: ������(��ά��)
#
# isbn_image: ���ꤷ��ISBN�ν�Ƥ�class="amazon"��ɽ��
#     asin:    ASIN�ޤ���ISBN(ɬ��)
#     comment: ������(��ά��)
#
# isbn_detail: ���ꤷ��ISBN�ν��Ҥ����դ��Ǿܺ�ɽ��
#     asin:    ASIN�ޤ���ISBN(ɬ��)
#
# isbn: amazon�˥����������ʤ��ʰץС������
#     asin:    ASIN�ޤ���ISBN(ɬ��)
#     comment: ������(ɬ��)
#
#   ASIN�Ȥϥ��ޥ����ȼ��ξ��ʴ���ID�Ǥ���
#   ���Ҥ�ISBN��ASIN�����Ϥ���Ƚ��Ҥ�ɽ������ޤ���
#
#   ���줾�쾦�ʲ��������Ĥ���ʤ��ä�����
#       <a href="amazon�Υڡ���">����̾</a>
#   �Τ褦�˾���̾��ɽ�����ޤ���
#   �����Ȥ����Ҥ���Ƥ�����Ͼ���̾�������Ȥ����Ƥ��Ѥ��ޤ���
#
# tdiary.conf�ˤ���������:
#   @options['amazon.aid']:      ������������ID����ꤹ�뤳�Ȥǡ���ʬ�Υ�
#                                ���������ȥץ��������ѤǤ��ޤ�
#                                ���Υ��ץ�����������̤����ѹ���ǽ�Ǥ�
#   @options['amazon.hideconf']: ������̾�ǥ�����������ID�������Բ�ǽ
#                                �ˤ�������硢true�����ꤷ�ޤ�
#   @options['amazon.imgsize']:  ɽ�����륤�᡼���Υ���������ꤷ�ޤ�
#                                (0:��  1:��  2:��)
#   @options['amazon.hidename']: class="amazon"�ΤȤ��˾���̾��ɽ��������
#                                �ʤ���硢true�����ꤷ�ޤ�
#   @options['amazon.default_image_base']: �ǥե���ȤΥ��᡼�����Ǽ����
#                                 URL����ꤷ�ޤ���̵������ˤ�tDiary.org
#                                 �ˤ����Τ��Ȥ��ޤ�������������ˤ�
#                                 �ץ饰����amazon�ǥ��쥯�ȥ�ˤ���PNG
#                                 �ե�����򻲹ͤˤ��Ʋ�����
#   @options['amazon.nodefault']: �ǥե���ȤΥ��᡼����ɽ���������ʤ����
#                                 true�����ꤷ�ޤ�
#
#
# ��ա��������Ϣ����١�www.amazon.co.jp�Υ����������ȥץ�����
# ��ǧ�ξ����Ѥ��Ʋ�������
#

@amazon_default_country = 'jp'
@amazon_item_name = /^Amazon.co.jp�� (.*)<.*$/
@amazon_item_image = %r|(<img src="(http://images-jp\.amazon\.com/images/P/(.*MZZZZZZZ_?.jpg))".*?>)|i
@amazon_label_conf ='Amazon'
@amazon_label_aid = 'Amazon������������ID�λ���'
@amazon_label_aid_desc = '���ꤷ�ʤ����ˤϡ�tDiary��Ԥν�ͭ����ID�����ꤵ�줿���Ȥˤʤ�ޤ��ΤǤ���դ���������'
@amazon_label_imgsize = 'ɽ�����륤�᡼���Υ�����'
@amazon_label_large = '�礭��'
@amazon_label_regular = '����'
@amazon_label_small = '������'
@amazon_label_title = 'isbn_image�ץ饰����Ǿ���̾��'
@amazon_label_hide = 'ɽ�����ʤ�'
@amazon_label_show = 'ɽ������'
@amazon_label_notfound = '���᡼�������Ĥ���ʤ��Ȥ���'
@amazon_label_usetitle = '����̾��ɽ������'
@amazon_label_usedefault = '�ǥե���ȤΥ��᡼����Ȥ�'
@amazon_label_clearcache = '����å���κ��'
@amazon_label_clearcache_desc = '���᡼����Ϣ����Υ���å����������(Amazon���ɽ����̷�⤬������˻�Ʋ�����)'
