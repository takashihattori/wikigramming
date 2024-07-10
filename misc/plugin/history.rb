# -*- coding: euc-jp -*-
=begin

== plugin/history.rb - CVS ���Խ������ɽ������ץ饰����

  Copyright (C) 2003 Hajime BABA <baba.hajime@nifty.com>
  $Id: history.rb,v 1.29 2007-09-24 21:23:09 fdiary Exp $
  You can redistribute and/or modify this file under the terms of the LGPL.

  Copyright (C) 2003 Yasuo Itabashi <yasuo_itabashi{@}hotmail.com>

=== �Ȥ���

* Hiki �� cvs �ץ饰���� (���뤤�� svn �ץ饰����) �����Ѥ��Ƥ���
  ���Ȥ�������Ǥ���

* ���ξ�ǡ�Hiki �Υץ饰����ǥ��쥯�ȥ�˥��ԡ�����С�
  ������˥塼�ˡ��Խ�����פ�����ƻȤ���褦�ˤʤ�ޤ���

=== �ܺ�

* �ʲ��λ��ĤΥץ饰���󥳥ޥ�ɤ��ɲä���ޤ���
    * history       �ڡ������Խ�����ΰ�����ɽ��
    * history_src   �����ӥ����Υ�������ɽ��
    * history_diff  Ǥ�դΥ�ӥ����֤κ�ʬ��ɽ��
  �ºݤˤϡ�
    @conf.cgi_name?c=history;p=FrontPage ��
    @conf.cgi_name?c=plugin;plugin=history_diff;p=FrontPage;r=2
  �Τ褦�˻��Ѥ��ޤ���

* ����ˤϥ֥�����������ʤ����Ȥ�����ˤ��Ƥ��ޤ���

* Subversion �б���Ŭ���Ǥ�(�ͤ��ȤäƤ��ʤ��Τ�)��

* �ץ饰��������κ�ˡ���褯�狼�äƤʤ��Τǡ��ɤʤ���ľ���Ƥ���������

=== history
2003/12/17 Yasuo Itabashi(Yas)    Subversion�б�, �ѹ��ս�ζ�Ĵ�б�, Ruby 1.7�ʹߤ��б�

=== notice
Hikifarm����Ѥ��Ƥ����硢hiki.conf��
@conf.repos_type      = (defined? repos_type) ? "#{repos_type}" : nil
���ɲä��Ƥ���������-- Yas

CSS��span.add_line, span.del_line�����ꤹ��ȡ��ѹ��ս��ʸ��°�����ѹ��Ǥ��ޤ���
-- Yas


=== SEE ALSO

* �����ν��Ϸ����� WiLiKi ���Խ�����򻲹ͤˤ����Ƥ��������ޤ�����
  http://www.shiro.dreamhost.com/scheme/wiliki/wiliki.cgi

=end

def history
  h = Hiki::History.new(@cgi, @db, @conf)
  h.history
end

def history_src
  h = Hiki::History.new(@cgi, @db, @conf)
  h.history_src
end

def history_diff
  h = Hiki::History.new(@cgi, @db, @conf)
  h.history_diff
end

add_body_enter_proc(Proc.new do
  add_plugin_command('history', history_label, {'p' => true})
end)

module Hiki
  class History < Command
    private

    def history_repos_type
      @conf.repos_type # 'cvs' or 'svn' or 'svnsingle'
    end

    def history_repos_root
      @conf.repos_root # hiki.conf
    end

    # Subroutine to invoke external command using `` sequence.
    def history_exec_command(cmd_string)
      Dir.chdir("#{@db.pages_path}") do
        `#{cmd_string.untaint}`
      end
    end

    # Subroutine to output proper HTML for Hiki.
    def history_output(s)
      # Imported codes from hiki/command.rb::cmd_view()
      parser = @conf.parser.new( @conf )
      tokens = parser.parse( s )
      formatter = @conf.formatter.new( tokens, @db, @plugin, @conf )
      @page  = Page.new( @cgi, @conf )
      data   = Util.get_common_data( @db, @plugin, @conf )
      pg_title = @plugin.page_name(@p)
      data[:tools]      = @plugin.create_global_menu
      data[:pagetools]  = @plugin.create_page_menu
      data[:title]      = title( "#{pg_title} - #{history_label}")
      data[:view_title] = "#{pg_title} - #{history_label}"
      data[:body]       = formatter.apply_tdiary_theme(s)

      @cmd = 'view' # important!!!
      generate_page(data) # private method inherited from Command class
    end

    def recent_revs(revs, rev)
      ind = revs.index(revs.assoc(rev)) || 0
      prev_rev = revs[ind + 1]
      prev2_rev = revs[ind + 2]
      if ind - 1 >= 0
        next_rev = revs[ind - 1]
      else
        next_rev = nil
      end
      [prev2_rev, prev_rev, revs[ind], next_rev]
    end

    def diff_link(rev1, rev2, rev_title1, rev_title2, link)
      title = []
      title << (rev_title1 || (rev1 and rev1[0]) || nil)
      title << (rev_title2 || (rev2 and rev2[0]) || nil)
      title = title.compact
      title.reverse! unless rev2.nil?
      title = title.join("<=>").escapeHTML

      do_link = (link and rev1)

      rv = "["
      if do_link
        rev_param = "r=#{rev1[0]}"
        rev_param << ";r2=#{rev2[0]}" if rev2
        rv << %Q[<a href="#{@conf.cgi_name}#{cmdstr('plugin', "plugin=history_diff;p=#{@p.escape};#{rev_param}")}" title="#{title}">]
      end
      rv << title
      if do_link
        rv << "</a>"
      end
      rv << "]\n"
      rv
    end

    public

    # Output summary of change history
    def history
      # parse the result and make revisions array
      revs = @conf.repos.revisions(@p)
      # construct output sources
      prevdiff = 1
      sources = ''
      sources << @plugin.hiki_anchor(@p.escape, @plugin.page_name(@p))
      sources << "\n<br>\n"
      sources << "\n<table border=\"1\">\n"
      if @conf.options['history.hidelog']
        case history_repos_type
        when 'cvs'
          sources << " <tr><th>#{history_th_label[0].escapeHTML}</th><th>#{history_th_label[1].escapeHTML}</th><th>#{history_th_label[2].escapeHTML}</th><th>#{history_th_label[3].escapeHTML}</th></tr>\n"
        else
          sources << " <tr><th>#{history_th_label[0].escapeHTML}</th><th>#{history_th_label[1].escapeHTML}</th><th>#{history_th_label[3].escapeHTML}</th></tr>\n"
        end
      else
        case history_repos_type
        when 'cvs'
          sources << " <tr><th rowspan=\"2\">#{history_th_label[0].escapeHTML}</th><th>#{history_th_label[1].escapeHTML}</th><th>#{history_th_label[2].escapeHTML}</th><th>#{history_th_label[3].escapeHTML}</th></tr><tr><th colspan=\"3\">#{history_th_label[4].escapeHTML}</th></tr>\n"
        else
          sources << " <tr><th rowspan=\"2\">#{history_th_label[0].escapeHTML}</th><th>#{history_th_label[1].escapeHTML}</th><th>#{history_th_label[3].escapeHTML}</th></tr><tr><th colspan=\"2\">#{history_th_label[4].escapeHTML}</th></tr>\n"
        end
      end
      revs.each do |rev,time,changes,log|
        #    time << " GMT"
        op = "[<a href=\"#{@conf.cgi_name}#{cmdstr('plugin', "plugin=history_src;p=#{@p.escape};r=#{rev}")}\">View</a> this version] "
        if revs.size != 1
          op << "[Diff to "
          op << "<a href=\"#{@conf.cgi_name}#{cmdstr('plugin', "plugin=history_diff;p=#{@p.escape};r=#{rev}")}\">current</a>" unless prevdiff == 1
          op << " | " unless (prevdiff == 1 || prevdiff >= revs.size)
          op << "<a href=\"#{@conf.cgi_name}#{cmdstr('plugin', "plugin=history_diff;p=#{@p.escape};r=#{rev};r2=#{revs[prevdiff][0]}")}\">previous</a>" unless prevdiff >= revs.size
          op << "]"
        end
        if @conf.options['history.hidelog']
          case history_repos_type
          when 'cvs'
            sources << " <tr><td>#{rev}</td><td>#{time.escapeHTML}</td><td>#{changes.escapeHTML}</td><td align=right>#{op}</td></tr>\n"
          else
            sources << " <tr><td>#{rev}</td><td>#{time.escapeHTML}</td><td align=right>#{op}</td></tr>\n"
          end
        else
          log.gsub!(/=============================================================================/, '')
          log.chomp!
          log = "*** no log message ***" if log.empty?
          case history_repos_type
          when 'cvs'
            sources << " <tr><td rowspan=\"2\">#{rev}</td><td>#{time.escapeHTML}</td><td>#{changes.escapeHTML}</td><td align=right>#{op}</td></tr><tr><td colspan=\"3\">#{log.escapeHTML}</td></tr>\n"
          else
            sources << " <tr><td rowspan=\"2\">#{rev}</td><td>#{time.escapeHTML}</td><td align=right>#{op}</td></tr><tr><td colspan=\"2\">#{log.escapeHTML}</td></tr>\n"
          end
        end
        prevdiff += 1
      end
      sources << "</table>\n"

      history_output(sources)
    end

    # Output source at an arbitrary revision
    def history_src
      # make command string
      r = @cgi.params['r'][0] || '1'
      txt = @conf.repos.get_revision(@p, r)
      txt = "*** no source ***" if txt.empty?

      # construct output sources
      sources = ''
      sources << "<div class=\"section\">\n"
      sources << @plugin.hiki_anchor(@p.escape, @plugin.page_name(@p))
      sources << "\n<br>\n"
      sources << "<a href=\"#{@conf.cgi_name}#{cmdstr('edit', "p=#{@p.escape};r=#{r.escapeHTML}")}\">#{history_revert_label.escapeHTML}</a><br>\n"
      sources << "<a href=\"#{@conf.cgi_name}#{cmdstr('plugin', "plugin=history_diff;p=#{@p.escape};r=#{r.escapeHTML}")}\">#{history_diffto_current_label.escapeHTML}</a><br>\n"
      sources << "<a href=\"#{@conf.cgi_name}#{cmdstr('history', "p=#{@p.escape}")}\">#{history_backto_summary_label.escapeHTML}</a><br>\n"
      sources << "</div>\n"
      sources << "<div class=\"diff\">\n"
      sources << txt.escapeHTML.gsub(/\n/, "<br>\n").gsub(/ /, '&nbsp;')
      sources << "</div>\n"

      history_output(sources)
    end

    # Output diff between two arbitrary revisions
    def history_diff
      # make command string
      r = @cgi.params['r'][0] || '1'
      r2 = @cgi.params['r2'][0]
      if r2.nil? || r2.to_i == 0
        new = @db.load(@p)
        old = @conf.repos.get_revision(@p, r)
      else
        new = @conf.repos.get_revision(@p, r)
        old = @conf.repos.get_revision(@p, r2)
      end

      # parse the result and make revisions array
      revs = @conf.repos.revisions(@p)

      prev2_rev, prev_rev, curr_rev, next_rev = recent_revs(revs, r.to_i)
      last_rev = revs[0]

      diff = word_diff( old, new )

      # construct output sources
      sources = ''
      sources << "<div class=\"section\">\n"
      sources << @plugin.hiki_anchor(@p.escape, @plugin.page_name(@p))
      sources << "<br>\n"
      sources << "<a href=\"#{@conf.cgi_name}#{cmdstr('plugin', "plugin=history_src;p=#{@p.escape};r=#{curr_rev[0]}")}\">#{history_view_this_version_src_label.escapeHTML}</a><br>\n" if curr_rev
      sources << "<a href=\"#{@conf.cgi_name}#{cmdstr('history', "p=#{@p.escape}")}\">#{history_backto_summary_label.escapeHTML}</a><br>\n"
      sources << "\n"

      if prev_rev
        do_link = (last_rev and prev_rev and last_rev[0] != prev_rev[0])
        sources << diff_link(prev_rev, nil, nil, "HEAD", do_link)
      end
      if prev_rev and prev2_rev
        sources << diff_link(prev_rev, prev2_rev, nil, nil, true)
      end
      sources << diff_link(curr_rev, r2.nil? ? nil : prev_rev, nil, nil, false)
      if next_rev
        sources << diff_link(next_rev, curr_rev, nil, nil, true)
      end
      do_link = (r2 and last_rev and last_rev[0] != curr_rev[0])
      sources << diff_link(curr_rev, nil, nil, "HEAD", do_link)

      sources << "</div>\n<br>\n"
      sources << "<ul>"
      sources << "  <li>#{history_add_line_label}</li>"
      sources << "  <li>#{history_delete_line_label}</li>"
      sources << "</ul>"
      sources << "<div class=\"diff\">#{diff.gsub(/\n/, "<br>\n")}</div>\n"

      history_output(sources)
    end
  end
end
