# $Id: util.rb,v 1.44 2005-12-25 07:03:06 yanagita Exp $
# Copyright (C) 2002-2003 TAKEUCHI Hitoshi <hitoshi@namaraii.com>

require 'nkf'
require 'cgi'

autoload( :Document, 'docdiff' )
autoload( :Diff, 'docdiff' )

class String
  # all instance methods added in String class will be obsoleted in the
  # future release.

  def to_euc
    NKF.nkf('-m0 -e', self)
  end

  def to_sjis
    NKF.nkf('-m0 -s', self)
  end

  def to_jis
    NKF.nkf('-m0 -j', self)
  end

  def escape
    CGI.escape(self).gsub(/%../) { |c| c.downcase }
  end

  def unescape
    CGI.unescape(self)
  end

  def escapeHTML
    CGI.escapeHTML(self)
  end

  def unescapeHTML
    CGI.unescapeHTML(self)
  end

  def sanitize
    self
  end
end

class Hash
  alias :key :index unless method_defined?(:key)
end

module Hiki
  class PluginException < Exception; end

  module Util
    def plugin_error( method, e )
      msg = "<strong>#{e.class} (#{e.message.escapeHTML}): #{method.escapeHTML}</strong><br>"
      msg << "<strong>#{e.backtrace.join("<br>\n")}</strong>" if @conf.plugin_debug
      msg
    end

    def cmdstr( cmd, param )
      "?c=#{cmd};#{param}"
    end

    def title( s )
      CGI.escapeHTML( "#{@conf.site_name} - #{s}" )
    end

    def view_title( s )
      %Q!<a href="#{@conf.cgi_name}#{cmdstr('search', "key=#{s.escape}") }">#{s.escapeHTML}</a>!
    end

    def format_date( tm )
      tm.strftime(@conf.msg_time_format).sub(/#DAY#/, "(#{@conf.msg_day[tm.wday]})")
    end

    def get_common_data( db, plugin, conf )
      data = Hash.new
      data[:author_name] = conf.author_name
      data[:view_style]  = conf.use_sidebar ? CGI.escapeHTML( conf.main_class ) : 'hiki' # for tDiary theme
      data[:cgi_name]    = conf.cgi_name
      if conf.use_sidebar
        t = db.load_cache( conf.side_menu )
        unless t
          m = db.load( conf.side_menu ) || ''
          parser = conf.parser.new( conf )
          t = parser.parse( m )
          db.save_cache( conf.side_menu, t )
        end
        f = conf.formatter.new( t, db, plugin, conf, 's' )
        data[:sidebar]   = f.to_s
        data[:main_class]    = conf.main_class
        data[:sidebar_class] = CGI.escapeHTML( conf.sidebar_class )
      else
        data[:sidebar] = nil
      end
      data
    end

    def word_diff( src, dst, digest = false )
      src_doc = Document.new( src, 'EUC-JP', CharString.guess_eol($/) )
      dst_doc = Document.new( dst, 'EUC-JP', CharString.guess_eol($/) )
      diff = compare_by_line_word( src_doc, dst_doc )
      overriding_tags = {
        :start_common => '',
        :end_common => '',
        :start_del           => '<del class="deleted">',
        :end_del             => '</del>',
        :start_add           => '<ins class="added">',
        :end_add             => '</ins>',
        :start_before_change => '<del class="deleted">',
        :end_before_change   => '</del>',
        :start_after_change  => '<ins class="added">',
        :end_after_change    => '</ins>',
      }
      if digest
        return View.new( diff, src.encoding, src.eol ).to_html_digest(overriding_tags, false).to_s.gsub( %r|<br />|, '' ).gsub( %r|\n</ins>|, "</ins>\n" )
      else
        return View.new( diff, src.encoding, src.eol ).to_html(overriding_tags, false).to_s.gsub( %r|<br />|, '' ).gsub( %r|\n</ins>|, "</ins>\n" )
      end
    end

    def word_diff_text( src, dst, digest = false )
      src_doc = Document.new( src, 'EUC-JP' )
      dst_doc = Document.new( dst, 'EUC-JP' )
      diff = compare_by_line_word( src_doc, dst_doc )
      if digest
        return View.new( diff, src.encoding, src.eol ).to_wdiff_digest({}, false).join.gsub( %r|\n\+\}|, "+}\n" )
      else
        return View.new( diff, src.encoding, src.eol ).to_wdiff({}, false).join.gsub( %r|\n\+\}|, "+}\n" )
      end
    end

    def unified_diff( src, dst, context_lines = 3 )
      return Diff.new(src.to_a, dst.to_a).ses.unidiff( '', context_lines )
    end

    def redirect(cgi, url, cookies = nil)
      url.sub!(%r|/\./|, '/')
      header = {}
      header['cookie'] = cookies if cookies
      header['type'] = 'text/html'
      print cgi.header(header)
      print %Q[
               <html>
               <head>
               <meta http-equiv="refresh" content="0;url=#{url}">
               <title>moving...</title>
               </head>
               <body>Wait or <a href="#{url}">Click here!</a></body>
               </html>]
    end

    def sendmail(subject, body)
      require 'net/smtp'
      require 'time'
      if @conf.mail && !@conf.mail.empty? && @conf.smtp_server
        Net::SMTP.start(@conf.smtp_server, 25) do |smtp|
          from_addr = @conf.mail_from ? @conf.mail_from : @conf.mail[0]
          from_addr.untaint
          to_addrs = @conf.mail
          to_addrs.each{|a| a.untaint}

          smtp.send_mail <<EndOfMail, from_addr, *to_addrs
From: #{from_addr}
To: #{to_addrs.join(",")}
Subject: #{NKF.nkf('-M', subject)}
Date: #{Time.now.rfc2822}
MIME-Version: 1.0
Content-Type: text/plain; charset="iso-2022-jp"
Content-Transfer-Encoding: 7bit
X-Mailer: Hiki #{Hiki::VERSION}

#{body.to_jis}
EndOfMail
        end
      end
    end

    def send_updating_mail(page, type, text='')
      body = <<EOS
#{'-' * 25}
REMOTE_ADDR = #{ENV['REMOTE_ADDR']}
REMOTE_HOST = #{ENV['REMOTE_HOST']}
EOS
      body << "REMOTE_USER = #{ENV['REMOTE_USER']}\n" if ENV['REMOTE_USER']
      body << <<EOS
        URL = #{@conf.index_url}?#{page.escape}
#{'-' * 25}
#{text}
EOS
      sendmail("[#{@conf.site_name}] #{type} - #{page}", body)
    end

    def theme_url
      if /\.css\Z/i =~ @conf.theme_url
        @conf.theme_url
      else
       "#{@conf.theme_url}/#{@conf.theme}/#{@conf.theme}.css"
      end
    end

    def base_css_url
      if /\.css\Z/i =~ @conf.theme_url
        "#{File.dirname(@conf.theme_url)}/../hiki_base.css"
      else
       "#{@conf.theme_url}/hiki_base.css"
      end
    end

    def set_conf(conf)
      @conf = conf
    end

    def shorten(str, len = 200)
      arr = str.split(//)
      if arr.length <= len - 2
        str
      else
        arr[0...len-2].join('') + '..'
      end
    end

    def euc_to_utf8(str)
      if NKF.const_defined?(:UTF8)
        return NKF.nkf('-m0 -w', str)
      else
        begin
          require 'uconv'
        rescue LoadError
            raise "Please update to Ruby >= 1.8.2, or install either uconv or rbuconv."
        end
        return Uconv.euctou8(str)
      end
    end

    def utf8_to_euc(str)
      if NKF.const_defined?(:UTF8)
        return NKF.nkf('-m0 -e', str)
      else
        begin
          require 'uconv'
        rescue LoadError
          raise "Please update to Ruby >= 1.8.2, or install either uconv or rbuconv."
        end
        return Uconv.u8toeuc(str)
      end
    end

    def to_native(str, charset=nil)
      # XXX to_charset will be 'utf-8' in the future version
      begin
        Iconv.conv(@charset, charset || 'utf-8', str)
      rescue
        from = case charset
               when /^utf-8$/i
                 'W'
               when /^shift_jis/i
                 'S'
               when /^EUC-JP/i
                 'E'
               else
                 ''
               end
        to = case @charset
               when /^utf-8$/i
                 'w'
               when /^shift_jis/i
                 's'
               when /^EUC-JP/i
                 'e'
               else
                 'e' # XXX what should we use?
               end
        NKF::nkf("-m0 -#{from}#{to}", str)
      end
    end

    def compare_by_line(doc1, doc2)
      Difference.new(doc1.split_to_line, doc2.split_to_line)
    end

    def compare_by_line_word(doc1, doc2)
      lines = compare_by_line(doc1, doc2)
      words = Difference.new
      lines.each{|line|
        if line.first == :change_elt
          before_change = Document.new(line[1].to_s,
                                       doc1.encoding, doc1.eol)
          after_change  = Document.new(line[2].to_s,
                                       doc2.encoding, doc2.eol)
          Difference.new(before_change.split_to_word,
                         after_change.split_to_word).each{|word|
            words << word
          }
        else  # :common_elt_elt, :del_elt, or :add_elt
          words << line
        end
      }
      words
    end
  end
end
