# -*- coding: undecided -*-
# $Id: command.rb,v 1.92 2008-02-12 15:06:08 hiraku Exp $
# Copyright (C) 2002-2004 TAKEUCHI Hitoshi <hitoshi@namaraii.com>

require 'timeout'
require 'hiki/page'
require 'hiki/util'
require 'hiki/plugin'
require 'hiki/aliaswiki'
require 'hiki/session'
require 'hiki/filter'
require 'hiki/scheme'

include Hiki::Util

module Hiki
  class PermissionError < StandardError; end
  class SessionError < StandardError
    def initialize(msg = nil)
      msg = 'Invalid Session (maybe timeout)' unless msg
      super
    end
  end

  class Command
    def initialize(cgi, db, conf)
      @db     = db
      @params = cgi.params
      @cgi    = cgi
      @conf   = conf
      code_conv

      # for TrackBack
      # if %r|/tb/(.+)$| =~ ENV['REQUEST_URI']
      #   @cgi.params['p'] = [CGI.unescape($1)]
      #   @cgi.params['c'] = ['plugin']
      #   @cgi.params['plugin'] = ['trackback_post']
      # end

      @cmd    = @params['c'][0]
      @p = case @params.keys.size
           when 0
             @p = 'FrontPage'
           when 1
             @cmd ? nil : @params.keys[0]
           else
             if @cmd == "create"
               @params['key'][0] ? @params['key'][0] : nil
             else
               @params['p'][0] ? @params['p'][0] : nil
             end
           end

      if /\A\.{1,2}\z/ =~ @p
        redirect(@cgi, @conf.index_url)
        return
      end

      @aliaswiki  = AliasWiki.new( @db.load( @conf.aliaswiki_name ) )
      @p = @aliaswiki.original_name(@p).to_euc if @p

      options = @conf.options || Hash.new( '' )
      options['page'] = @p
      options['db']   = @db
      options['cgi']  = cgi
      options['alias'] = @aliaswiki
      options['command'] = @cmd ? @cmd : 'view'
      options['params'] = @params

      @plugin = Plugin.new( options, @conf )
      session_id = @cgi.cookies['session_id'][0]
      if session_id
        session = Hiki::Session.new( @conf, session_id )
        if session.check
          @plugin.user = session.user
          @plugin.session_id = session_id
        end
      end
      if @conf.use_session && !@plugin.session_id
        session = Hiki::Session.new( @conf )
        session.save
        @plugin.session_id = session.session_id
        @plugin.add_cookie( session_cookie( @plugin.session_id ))
      end
      @body_enter = @plugin.body_enter_proc

      Filter.init(@conf, @cgi, @plugin, @db)
    end

    def dispatch
      begin
        Timeout.timeout(@conf.timeout) {
          if 'POST' == @cgi.request_method
            raise PermissionError, 'Permission denied' unless @plugin.postable?
          end
          @cmd = 'view' unless @cmd
          raise if !@p && ['view', 'edit', 'diff', 'save'].index( @cmd )
          if @cmd == 'edit'
            raise PermissionError, 'Permission denied' unless @plugin.editable?
            cmd_edit( @p )
          elsif @cmd == 'save'
            raise PermissionError, 'Permission denied' unless @plugin.editable?
            if @params['save'][0]
              cmd_save
            elsif @params['cancel'][0]
              @cmd = 'view'
              cmd_view
            elsif @params['edit_form_button'][0]
              @cmd = 'edit'
              cmd_plugin(false)
              cmd_edit( @p, @plugin.text )
            else
              cmd_preview
            end
          elsif @cmd == 'create'
            raise PermissionError, 'Permission denied' unless @plugin.editable?
            send( "cmd_#{@cmd}" )
          else
            if @conf.use_plugin and @plugin.plugin_command.index(@cmd) and @plugin.respond_to?(@cmd)
              @plugin.send( @cmd )
            else
              send( "cmd_#{@cmd}" )
            end
          end
        }
      rescue NoMethodError, PermissionError, SessionError, Timeout::Error
        data = get_common_data( @db, @plugin, @conf )
        data[:message] = CGI.escapeHTML( $!.message )
        generate_error_page( data )
      end
    end

  private
    def generate_page( data, status = 'OK' )
#      @plugin.hiki_menu(data, @cmd)
      data[:tools] = @plugin.create_global_menu
      data[:pagetools] = @plugin.create_page_menu if @p
      @plugin.title = data[:title]
      data[:cmd] = @cmd
      data[:cgi_name] = @conf.cgi_name
      data[:body_enter] = @body_enter
      data[:lang] = @conf.lang
      data[:header] = @plugin.header_proc
      data[:body_leave] = @plugin.body_leave_proc
      data[:page_attribute] ||= ''
      data[:footer] = @plugin.footer_proc
      data.update( @plugin.data ) if @plugin.data
      if data[:toc]
        data[:body] = data[:toc] + data[:body] if @plugin.toc_f == :top
        data[:body].gsub!( Regexp.new( Regexp.quote( Plugin::TOC_STRING ) ), data[:toc] )
      end

      @page = Hiki::Page.new( @cgi, @conf )
      @page.template = @conf.read_template( @cmd )
      @page.contents = data

      data[:last_modified] = Time.now unless data[:last_modified]
      @page.process( @plugin )
      @page.out( 'status' => status )
    end

    def generate_error_page( data )
#      @plugin.hiki_menu(data, @cmd)
      data[:tools] = @plugin.create_global_menu
      @plugin.title = title( 'Error' )
      data[:cgi_name] = @conf.cgi_name
      data[:view_title] = 'Error'
      data[:header] = @plugin.header_proc
      data[:frontpage] = @plugin.page_name( 'FrontPage' )
      @page = Hiki::Page.new( @cgi, @conf )
      @page.template = @conf.read_template( 'error' )
      @page.contents = data
      @page.process( @plugin )
      @page.out( 'status' => 'NOT_FOUND' )
    end

    def cmd_apply
      @cmd = 'apply'
      func = @plugin.page_name(@p)
      args = @params['arg'][0]
      if args
        exp = "(#{func} #{args})"
        result = exp + "<br/> => "
        if check_syntax exp
          r, o = call_scheme(exp, "(load \"#{func.escape}\")")
          result += r.escapeHTML
          o = o.escapeHTML
          args = nil
        else
          result += "ERROR"
          o = @conf.msg_unbalanced_paren
        end
      end
      data               = get_common_data( @db, @plugin, @conf )
      data[:method]      = 'post'
      data[:title]       = title( func )
      data[:apply_title] = "#{func} - Apply"
      data[:func]        = @plugin.page_name(@p)
      data[:arg]         = args
      data[:msg1]        = result
      data[:msg2]        = o
      data[:button]      = @conf.msg_evalsubmit
      data[:newer]  = find_newer.collect{|x| "[#{@plugin.make_history_anchor(x)}] "}.join
      generate_page( data )
    end

    def check_syntax (x)
      nest = 0
      i = 0
      while (i < x.length) do
        case x[i]
        when ?(
          nest += 1
        when ?)
          nest -= 1
          return false if nest < 0 || (nest == 0 && i < x.length-1)
        when ?"
          begin
            i += 1
            i += 2 if x[i] == 92
            return false if i >= x.length
          end while x[i] != ?"
        when ?#
          i += 2 if x[i+1] == 92
        end
        i += 1
      end
      nest == 0
    end

    def find_newer
      depends = []
      new_depends = @db.get_attribute(@p, :references)
      while depends != new_depends do
        depends = new_depends
        new_depends = (depends + (depends.collect{ |x| @db.get_attribute(x, :references) }.flatten)).uniq
      end
      this_time = @db.get_last_update( @p )
      depends.delete_if { |x| @db.get_last_update(x) < this_time }
    end

    def cmd_preview
      raise SessionError if @plugin.session_id && @plugin.session_id != @cgi['session_id']
      @cmd = 'preview'
      cmd_edit( @p, @params['contents'][0], @conf.msg_preview, @params['page_title'][0] )
    end

    def cmd_view
      unless @db.exist?( @p )
        @cmd = 'create'
        cmd_create( @conf.msg_page_not_exist )
        return
      end

      tokens = @db.load_cache( @p )
      unless tokens
        text = @db.load( @p )
        pos = (text =~ /^\(define/)
        if pos
          wiki_text = unindent($`, ';;') + "\n<<<\n" + text[pos..-1] + ">>>\n"
        else
          wiki_text = text
        end
        parser = @conf.parser.new( @conf )
        tokens = parser.parse( wiki_text )
        @db.save_cache( @p, tokens )
      end
      formatter = @conf.formatter.new( tokens, @db, @plugin, @conf )

      pg_title = @plugin.page_name(@p)

      data = get_common_data( @db, @plugin, @conf )

      data[:func]         = pg_title
      data[:title]        = title( pg_title.unescapeHTML )
      data[:body]         = formatter.apply_tdiary_theme(formatter.to_s)
      data[:references]   = @db.get_attribute(@p, :references).collect {|f| "[#{@plugin.hiki_anchor(f.escape, @plugin.page_name(f))}] " }.join
      data[:last_modified]  = @db.get_last_update( @p )
      data[:page_attribute] = @plugin.page_attribute_proc
      data[:newer]  = find_newer.collect{|x| "[#{@plugin.make_history_anchor(x)}] "}.join

      generate_page( data )
    end

    def hilighten(str, keywords)
      hilighted = str.dup
      keywords.each do |key|
        re = Regexp.new('(' << Regexp.escape(key) << ')', Regexp::IGNORECASE)
        hilighted.gsub!(/([^<]*)(<[^>]*>)?/) {
          body, tag = $1, $2
          body.gsub(re) {
            %Q[<em class="hilight">#{$1}</em>]
          } << ( tag || "" )
        }
      end
      hilighted
    end

    def cmd_index
      list = @db.page_info.sort_by {|e|
        k,v = e.to_a.first
        if v[:title] && !v[:title].empty?
          v[:title].downcase
        else
          k.downcase
        end
      }.collect {|f|
        k = f.keys[0]
        editor = f[k][:editor] ? "by #{f[k][:editor]}" : ''
        display_text = ((f[k][:title] and f[k][:title].size > 0) ? f[k][:title] : k).escapeHTML
        display_text << " [#{@aliaswiki.aliaswiki(k)}]" if k != @aliaswiki.aliaswiki(k)
        %Q!#{@plugin.hiki_anchor(k.escape, display_text)}: #{format_date(f[k][:last_modified] )} #{editor}#{@conf.msg_freeze_mark if f[k][:freeze]}!
      }

      data = get_common_data( @db, @plugin, @conf )

      data[:title]     = title( @conf.msg_index )
      data[:updatelist] = list

      generate_page( data )
    end

    def cmd_recent
      list, last_modified = get_recent

      data = get_common_data( @db, @plugin, @conf )

      data[:title]      = title( @conf.msg_recent )
      data[:updatelist] = list
      data[:last_modified] = last_modified

      generate_page( data )
    end

    def get_recent
      list = @db.page_info.sort_by {|e|
        k,v = e.to_a.first
        v[:last_modified]
      }.reverse

      last_modified = list[0].values[0][:last_modified]

      list.collect! {|f|
        k = f.keys[0]
        tm = f[k][:last_modified]
        editor = f[k][:editor] ? "by #{f[k][:editor]}" : ''
        display_text = (f[k][:title] and f[k][:title].size > 0) ? f[k][:title] : k
        display_text = display_text.escapeHTML
        display_text << " [#{@aliaswiki.aliaswiki(k)}]" if k != @aliaswiki.aliaswiki(k)
        %Q|#{format_date( tm )}: #{@plugin.hiki_anchor( k.escape, display_text )} #{editor.escapeHTML} (<a href="#{@conf.cgi_name}#{cmdstr('diff',"p=#{k.escape}")}">#{@conf.msg_diff}</a>)|
      }
      [list, last_modified]
    end

    def cmd_edit( page, text=nil, msg=nil, d_title=nil )
      page_title = d_title ? d_title.escapeHTML : @plugin.page_name(page)

      save_button = @cmd == 'edit' ? '' : nil
      preview_text = nil
      differ       = nil
      link         = nil
      formatter    = nil
      data = get_common_data( @db, @plugin, @conf )
      if @db.is_frozen?( page ) || @conf.options['freeze']
        data[:freeze] = ' checked'
      else
        data[:freeze] = ''
      end

      if @cmd == 'preview'
        p = @conf.parser.new( @conf ).parse( text.gsub(/\r/, '') )
        formatter = @conf.formatter.new( p, @db, @plugin, @conf )
        preview_text, toc = formatter.to_s, formatter.toc
        save_button = ''
        data[:keyword] = CGI.escapeHTML( @params['keyword'][0] || '' )
        data[:freeze] = @params['freeze'][0] ? ' checked' : ''
      elsif @cmd == 'conflict'
        old = text.gsub(/\r/, '')
        new = @db.load( page ) || ''
        differ = word_diff( old, new ).gsub( /\n/, "<br>\n" )
        link = @plugin.hiki_anchor( page.escape, page.escapeHTML )
      end

      @cmd = 'edit'

      if rev = @params['r'][0]
        text = @conf.repos.get_revision(page, rev.to_i)
        raise 'No such revision.' if text.empty?
      else
        text = ( @db.load( page ) || '' ) unless text
      end
      md5hex = @params['md5hex'][0] || @db.md5hex( page )

      if text != ''
        text =~ /^\(define[^(]*\( *[^ ]+ +(.*)\)[^)]*\n/
        arg = $1
        doc = unindent($`, ";;")
        $' =~ /\)\n\(wiki-require.*\n/
        src = unindent($`)
        req = unindent($')[0..-2]
      else
        doc = arg = src = req = ''
      end

      @plugin.text = text

      data[:title]          = title( page )
      data[:edit_title]     = "#{page} - Edit"
      data[:toc]            = @plugin.toc_f ? toc : nil
      data[:pagename]       = page.escapeHTML
      data[:md5hex]         = md5hex
      data[:edit_proc]      = @plugin.edit_proc
      data[:msg]            = msg
      data[:preview_button] = save_button
      data[:link]           = link
      data[:differ]         = differ
      data[:body] = preview_text ? formatter.apply_tdiary_theme(preview_text) :  nil
      data[:doc]            = doc.escapeHTML
      data[:fun]            = page_title
      data[:arg]            = arg.escapeHTML
      data[:src]            = src.escapeHTML
      data[:req]            = req.escapeHTML
      data[:form_proc]      = @plugin.form_proc
      data[:session_id]     = @plugin.session_id

      generate_page( data )
    end

    def cmd_diff
      old = @db.load_backup( @p ) || ''
      new = @db.load( @p ) || ''
      differ = word_diff( old, new ).gsub( /\n/, "<br>\n" )

      data = get_common_data( @db, @plugin, @conf )

      data[:title]        = title("#{@p} #{@conf.msg_diff}")
      data[:differ]       = differ
      generate_page( data )
    end

    def indent(text, prefix = '  ')
      text.split("\n").collect { |line| prefix+line }.join("\n")
    end

    def unindent(text, prefix = '  ')
      text.split("\n").collect { |line|  
        line[0..1] == prefix ? line[2..-1] : line 
      }.join("\n")
    end

    def cmd_delete
        @db.delete( page )
        @plugin.delete_proc
        data             = get_common_data( @db, @plugin, @conf )
        data[:title]     = @conf.msg_delete
        data[:msg]       = @conf.msg_delete_page
        data[:link]      = page.escapeHTML
        generate_page(data)
    end

    def cmd_save
      raise SessionError if @plugin.session_id && @plugin.session_id != @cgi['session_id']

      title = @params['page_title'][0] ? @params['page_title'][0].strip : @p
      title = title.size > 0 ? title : @p
      doc = indent(@params['doc'][0], ';;')
      func = "(define (#{title} #{@params['arg'][0]})\n#{indent(@params['src'][0])})"
      req = "(wiki-require\n#{indent(@params['req'][0])})"
      text = "#{doc}\n#{func}\n#{req}\n"

      if exist?(title)
        @cmd = 'edit'
        cmd_edit( @p, text, @conf.msg_duplicate_page_title )
        return
      end

      if Filter.new_page_is_spam?(@p, text, title)
        @cmd = 'is_spam'
        cmd_edit( @p, text, @conf.msg_input_is_spam )
        return
      end

      if !check_syntax(func) || !check_syntax(req)
        @cmd = 'edit'
        cmd_edit( @p, text, @conf.msg_unbalanced_paren )
        return
      end

      result, output = call_scheme("(wiki-test #{@params['req'][0]})")
      if  result != '#t'
        @cmd = 'edit'
        cmd_edit( @p, text, result.escapeHTML )
        return
      end

      @db.select{ |p| p[:references] && p[:references].index(title) }.each do |p|
        exp = @db.load(p)
        pos_req = exp.index("(wiki-require")
        exp = exp[pos_req+13 .. -3]
        r, o = call_scheme("(wiki-test-func '#{title} '(#{exp}))", "(begin #{req} #{func})")
        if r != '#t'
          @cmd = 'edit'
          cmd_edit( @p, text, r.escapeHTML )
          return
        end
      end

      if @plugin.save( @p, text, @params['md5hex'][0], true, false )
        r, o = call_scheme("(map (lambda (x) (car x)) '(#{@params['req'][0]}))")
        attr = [[:title, title], 
                [:editor, @plugin.user],
                [:references, r[1..-2].escapeHTML.split(' ')]]
        @db.set_attribute(@p, attr)
      else
        @cmd = 'conflict'
        cmd_edit( @p, text, @conf.msg_save_conflict )
        return
      end

      @db.freeze_page( @p, @params['freeze'][0] ? true : false) if @plugin.admin?
      redirect(@cgi, @conf.base_url + @plugin.hiki_url(@p))
    end

    def cmd_search
      data             = get_common_data( @db, @plugin, @conf )
      data[:title]     = title( @conf.msg_search )
      data[:msg1]      = nil
      data[:msg2]      = nil
      data[:button]    = @conf.msg_search
      data[:list]      = nil
      data[:method]  = 'post'
      generate_page( data )
    end

    def cmd_searchname
      word = @params['key'][0]
      l = (word && word.size > 0) ? @db.select{ |p| p[:title].index(word) } : []
      search_result "Function name: #{word}", l
    end

    def cmd_searchspec
      arg = @params['arg'][0]
      result = @params['result'][0]
      exp = "(equal? (%s #{arg}) #{result})"
      query = "Specification: #{sprintf(exp, '???')}"
      if check_syntax(exp)
        l = @db.select do |p| 
          r, o = call_scheme(sprintf(exp, p[:title]), "(load \"#{p[:title]}\")")
          r == '#t' 
        end
        search_result query, l
      else
        search_result query, [], @conf.msg_unbalanced_paren
      end
    end

    def search_result(q, l, err = nil)
      q = q.escapeHTML
      l.collect! { |p| @plugin.make_anchor("#{@conf.cgi_name}?c=view&p=#{p.escape}", @plugin.page_name(p)) }
      data             = get_common_data( @db, @plugin, @conf )
      data[:title]     = title( @conf.msg_search_result )
      data[:button]    = @conf.msg_search
      if l.size > 0
        data[:msg1]    = sprintf( @conf.msg_search_hits, q, l.size )
        data[:list]    = l
      else
        data[:msg1]    = sprintf( @conf.msg_search_not_found, q )
        data[:list]    = nil
        data[:arg]     = @params['arg'][0]
        data[:result]  = @params['result'][0]
      end
      data[:msg2]      = err
      data[:method]    = 'post'
      generate_page( data )
    end

    def cmd_create( msg = nil )
      p = @params['key'][0]
      if p
        @p = @aliaswiki.original_name(p).to_euc
        if /^\./ =~ @p || @p.size > @conf.max_name_size || @p.size == 0
          @params['key'][0] = nil
          cmd_create( @conf.msg_invalid_filename( @conf.max_name_size) )
          return
        end

        @cmd = 'edit'

        orig_page = exist?(@p)
        if orig_page or @db.exist?(@p)
          s = @db.load( @p )
          cmd_edit( orig_page || @p, s, @conf.msg_already_exist )
        else
          cmd_edit( @p, @params['text'][0] )
        end
      else

        data           = get_common_data( @db, @plugin, @conf )
        data[:title]   = title( @conf.msg_create )
        data[:msg1]    = msg
        data[:msg2]    = @conf.msg_create + ': '
        data[:button]  = @conf.msg_newpage
        data[:key]     = %Q|value="#{msg ?  @p.escapeHTML :  ''}"|
        data[:list]    = nil
        data[:method]  = 'get'

        generate_page( data )
      end
    end

    def cmd_login
      name = @params['name'][0]
      password = @params['password'][0]
      page = @params['p'][0]
      msg_login_result = nil
      status = 'OK'
      if name && password
        session = Hiki::Session.new( @conf )
        @plugin.login( name, password )

        if @plugin.user
          session.user = @plugin.user
          session.save
          if page && !page.empty?
            redirect(@cgi, @conf.base_url + @plugin.hiki_url( page ), session_cookie( session.session_id ))
          else
            redirect(@cgi, @conf.index_url, session_cookie( session.session_id ))
          end
          return
        else
          msg_login_result = @conf.msg_login_failure
          status = '403 Forbidden'
        end
      end

      data = get_common_data( @db, @plugin, @conf )
      data[:title]   = title( @conf.msg_login )
      data[:button]  = @conf.msg_ok
      data[:login_result] = msg_login_result
      data[:page] = ( page || '' ).escapeHTML
      generate_page( data, status )
    end

    def cmd_admin
      raise PermissionError, 'Permission denied' unless @plugin.admin?

      data = get_common_data( @db, @plugin, @conf )
      data[:key]            = ( @cgi.params['conf'][0] || 'default' ).escapeHTML

      data[:title]          = title( @conf.msg_admin )
      data[:session_id]     = @plugin.session_id
      if @cgi.params['saveconf'][0]
        raise SessionError if @plugin.session_id && @plugin.session_id != @cgi['session_id']
        data[:save_config]    = true
      end
      generate_page( data )
    end

    def exist?( page )
      tmp = @aliaswiki.aliaswiki(page)
      if page != tmp and @p != page
        return @p
      end

      tmp =  @aliaswiki.original_name(page)
      if page != tmp and @p != tmp
      return tmp
      end

      p = (@db.select {|p| p[:title] and p[:title].unescape == page})[0]
      if p != @p and p != nil
        return p
      end

      if @db.exist?(page) and @p != page
        return page
      end

      false
    end

    def cmd_plugin(redirect_mode = true)
      return unless @conf.use_plugin
      plugin = @params['plugin'][0]

      result = true
      if @plugin.respond_to?( plugin ) && !Object.method_defined?( plugin )
        result = @plugin.send( plugin )
      else
        raise PluginException, 'not plugin method'
      end

      if redirect_mode and result
        redirect(@cgi, @conf.base_url + @plugin.hiki_url(@p))
      end
    end

    def cmd_logout
      if session_id = @cgi.cookies['session_id'][0]
        cookies = [session_cookie(session_id, -1)]
        Hiki::Session.new( @conf, session_id ).delete
      end
      redirect(@cgi, @conf.index_url, cookies)
    end

    def cookie(name, value, max_age = Session::MAX_AGE)
      CGI::Cookie.new( {
                          'name' => name,
                          'value' => value,
                          'path' => @plugin.cookie_path,
                          'expires' => Time.now.gmtime + max_age
                        } )
    end

    def session_cookie(session_id, max_age = Session::MAX_AGE)
      cookie('session_id', session_id, max_age)
    end

    def code_conv
      if @conf.mobile_agent? && /EUC-JP/i =~ @conf.charset
        @params.each_key do |k|
          @params[k].each do |v|
            v.replace(v.to_euc) if v
          end
        end
      end
    end
  end
end
