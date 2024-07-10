def history_label
  '�Խ�����'
end

module Hiki
  class History < Command
    private

    def history_label
      '�Խ�����'
    end

    def history_th_label
      ['Rev', '����', '�ѹ�', '���', '��']
    end

    def history_not_supported_label
      '���ߤ�����Ǥ��Խ�����ϥ��ݡ��Ȥ���Ƥ��ޤ���'
    end

    def history_revert_label
      '���ΥС��������᤹'
    end

    def history_diffto_current_label
      '���ߤΥС������Ȥκ�ʬ�򸫤�'
    end

    def history_view_this_version_src_label
      '���ΥС������Υ������򸫤�'
    end

    def history_backto_summary_label
      '�Խ�����ڡ��������'
    end

    def history_add_line_label
      '�ɲä��줿��ʬ��<ins class="added">���Τ褦��</ins>ɽ�����ޤ���'
    end

    def history_delete_line_label
      '������줿��ʬ��<del class="deleted">���Τ褦��</del>ɽ�����ޤ���'
    end
  end
end
