# -*- coding: euc-jp -*-
# $Id: attach.rb,v 1.7 2007-06-24 12:00:11 fdiary Exp $
# Copyright (C) 2003 TAKEUCHI Hitoshi <hitoshi@namaraii.com>
#
# thanks to Kazuhiko, Masao Mutoh, SHIMADA Mitsunobu, Yoshimi, �ꤿ

@options['attach.form'] ||= 'edit'

def attach_form(s = '')
  command = @command == 'create' ? 'edit' : @command
  attach_cgi = @options['attach.cgi_name'] || 'attach.cgi'
  <<EOS
<div class="form">
<form class="nodisp" method="post" enctype="multipart/form-data" action="#{attach_cgi}">
  <div>
    <input type="hidden" name="p" value="#{@page.escapeHTML}">
    <input type="hidden" name="command" value="#{command}">
    <input type="file" name="attach_file">
    <input type="submit" name="attach" value="#{attach_upload_label}">
  </div>
  <div>
    #{s}
  </div>
  #{attach_usage}
</form>
</div>
EOS
end

def attach_map
  attach_files = attach_all_files
  return '' if attach_files.size == 0

  s = "<ul>\n"
  attach_files.sort do |a, b|
    a[0].unescape <=> b[0].unescape
  end.each do |attach_info|
    s << "<li>#{hiki_anchor(attach_info[0], page_name(attach_info[0].unescape))}</li>\n"
    s << "<ul>\n"
    attach_info[1].each do |f|
      s << "<li>#{attach_anchor(f, attach_info[0].unescape)}</li>\n"
    end
    s << "</ul>\n"
  end
  s << "</ul>\n"
end

def attach_anchor_string(string, file_name, page = @page)
  s =  %Q!<a href="!
  s << %Q!#{@conf.cgi_name}#{cmdstr('plugin', "plugin=attach_download;p=#{page.escape};file_name=#{file_name.escape}")}">!
  s << %Q!#{if string then string.escapeHTML else file_name.escapeHTML end}</a>!
end

def attach_anchor(file_name, page = @page)
  s =  %Q!<a href="!
  s << %Q!#{@conf.cgi_name}#{cmdstr('plugin', "plugin=attach_download;p=#{page.escape};file_name=#{file_name.escape}")}">!
  s << %Q!#{file_name.escapeHTML}</a>!
end

def get_image_size(file_name, page = @page)
  begin
    require 'image_size'
    f = "#{@cache_path}/attach/#{page.escape}/#{file_name.escape}"
    File.open(f.untaint,'rb') do |fh|
      return ImageSize.new(fh).get_size
    end
  rescue
    return nil
  end
end

def attach_image_anchor(file_name, page = @page)
  image_size = get_image_size(file_name, page)
  s =  %Q!<img alt="#{file_name.escapeHTML}"!
  s << %Q! width="#{image_size[:width]}" height="#{image_size[:height]}"! if image_size
  if @conf.options['attach.cache_url']
    s << %Q! src="#{@conf.options['attach.cache_url']}/#{page.escape.escape}/#{file_name.escape}">!
  else
    s << %Q! src="#{@conf.cgi_name}#{cmdstr('plugin', "plugin=attach_download;p=#{page.escape};file_name=#{file_name.escape}")}">!
  end
end

def attach_flash_anchor(file_name, page = @page)
  image_size = get_image_size(file_name, page)
  s =  %Q!<embed type="application/x-shockwave-flash" src="!
  s << %Q!#{@conf.cgi_name}#{cmdstr('plugin', "plugin=attach_download;p=#{page.escape};file_name=#{file_name.escape}")}" !
  s << %Q! width="#{image_size[:width]}" height="#{image_size[:height]}" ! if image_size
  s << %Q!>!
end

def attach_download
  require 'image_size'
  params      = @cgi.params
  page        = (params['p'][0] || '')
  file_name   = (params['file_name'][0] || '')
  attach_file = "#{@cache_path}/attach/#{page.escape}/#{file_name.escape}"
  extname     =  /\.([^.]+)$/.match(file_name.downcase).to_a[1]
  if File::exist?( attach_file.untaint )
    mime_type = nil
    File.open(attach_file.untaint, 'rb') do |fh|
      mime_type = ImageSize.new(fh).mime_type
    end

    header = Hash::new
    header['Content-Type'] = mime_type
    header['Content-Length'] = File.size(attach_file.untaint)
    header['Last-Modified'] = CGI::rfc1123_date(File.mtime(attach_file.untaint))
    if %r|^image/| =~ mime_type
      header['Content-Disposition'] = %Q|inline; filename="#{file_name.to_sjis}"; modification-date="#{header['Last-Modified']}";|
    else
      header['Content-Disposition'] = %Q|attachment; filename="#{file_name.to_sjis}"; modification-date="#{header['Last-Modified']}";|
    end
    print @cgi.header(header)
    print File.open(attach_file.untaint, 'rb').read
  else
    data = get_common_data( @db, @plugin, @conf )
    generate_error_page( data )
  end
  nil
end

def attach_src(file_name, page = @page)
  tabstop = ' ' * (@options['attach.tabstop'] ? @options['attach.tabstop'].to_i : 2)

  if file_name =~ /\.(txt|rd|rb|c|pl|py|sh|java|html|htm|css|xml|xsl|sql|yaml)\z/i
    file = "#{@conf.cache_path}/attach/#{page.untaint.escape}/#{file_name.untaint.escape}"
    s = %Q!<pre>!
    content = File::readlines(file)
    if @options['attach.show_linenum']
      line = 0
      content.collect! {|i| sprintf("%3d| %s", line+=1, i)}
    end
    s << content.join.escapeHTML.gsub(/^\t+/) {|t| tabstop * t.size}.to_euc
    s << %Q!</pre>!
  end
end

def attach_view(file_name, page = @page)
  if file_name =~ /\.(txt|rd|rb|c|pl|py|sh|java|html|htm|css|xml|xsl)\z/i
    attach_src(file_name, page)
  elsif file_name =~ /\.(jpeg|jpg|png|gif|bmp)\z/i
    attach_image_anchor(file_name, page)
  end
end

def attach_page_files
  result = Array::new
  attach_path = "#{@cache_path}/attach/#{@page.escape}".untaint
  if FileTest::directory?(attach_path)
    Dir.entries(attach_path).collect do |file_name|
      result << file_name if FileTest::file?("#{attach_path}/#{file_name}".untaint)
    end
  end
  result
end

def attach_all_files
  attach_files = Hash.new([])
  return [] unless File::exist?("#{@cache_path}/attach/")

  Dir.foreach("#{@cache_path}/attach/") do |dir|
    next if /^\./ =~ dir
    attach_files[File.basename(dir)] = Dir.glob("#{@cache_path}/attach/#{dir.untaint}/*").collect do |f|
      File.basename(f).unescape
    end
  end
  attach_files.to_a
end

def attach_show_page_files
  s = ''
  if (files = attach_page_files).size > 0
    s << %Q!<p>#{attach_files_label}: \n!
    files.each do |file_name|
      f = file_name.unescape
      case @conf.charset
      when 'EUC-JP'
        f = file_name.unescape.to_euc
      when 'Shift_JIS'
        f = file_name.unescape.to_sjis
      end
      s << %Q! [#{attach_anchor(f)}] !
    end
    s << "</p>\n"
  end
  s
end

def attach_show_page_files_checkbox
  attach_cgi = @options['attach.cgi_name'] || 'attach.cgi'
  s =  ''
  if (files = attach_page_files).size > 0
     s << %Q!<form method="post" enctype="multipart/form-data" action="#{attach_cgi}">
  <input type="hidden" name="p" value="#{@page.escapeHTML}">
  <input type="hidden" name="command" value="#{@command == 'create' ? 'edit' : @command}">
  <p>#{attach_files_label}: 
!
    files.each do |file_name|
      f = file_name.unescape
      case @conf.charset
      when 'EUC-JP'
        f = file_name.unescape.to_euc
      when 'Shift_JIS'
        f = file_name.unescape.to_sjis
      end
      s << %Q! [<input type="checkbox" name="file_#{file_name.escapeHTML}">#{attach_anchor(f)}] \n!
    end
    s << %Q!<input type="submit" name="detach" value="#{detach_upload_label}">\n</p>\n</form>\n!
  end
  s
end


add_body_leave_proc {
  begin
    s = case @options['attach.form']
    when 'view', 'both'
      attach_form(attach_show_page_files)
    else
      ''
    end
  rescue Exception
  end
}

add_form_proc {
  begin
    s = case @options['attach.form']
    when 'edit', 'both'
      attach_form(attach_show_page_files_checkbox)
    else
      ''
    end
  rescue Exception
  end
}

export_plugin_methods(:attach_form, :attach_map, :attach_anchor_string, :attach_anchor, :attach_image_anchor, :attach_flash_anchor, :attach_download, :attach_src, :attach_view)
