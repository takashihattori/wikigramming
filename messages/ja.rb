# -*- coding: euc-jp -*-
# $Id: ja.rb,v 1.15 2008-02-12 15:06:08 hiraku Exp $
# Copyright (C) 2002-2003 TAKEUCHI Hitoshi <hitoshi@namaraii.com>
# You can redistribute it and/or modify it under the terms of
# the Ruby's licence.
module Hiki
  module Messages_ja
    def msg_recent; '更新履歴' end
    def msg_evalsubmit; '実行' end
    def msg_create; '新規作成' end
    def msg_view; '表示' end
    def msg_apply; 'Apply' end
    def msg_diff; '差分' end
    def msg_edit; '編集' end
    def msg_search; '検索' end
    def msg_admin; '管理' end
    def msg_login; 'ログイン' end
    def msg_logout; 'ログアウト' end
    def msg_search_name; '関数名による検索' end
    def msg_search_spec; '仕様による検索' end
    def msg_search_result; '検索結果' end
    def msg_search_hits; '\'%s\'に該当する関数が%d個見つかりました。' end
    def msg_search_not_found; '\'%s\'に該当する関数は見つかりませんでした。' end
    def msg_frontpage; 'トップ' end
    def msg_hitory; '更新履歴' end
    def msg_index; 'ページ一覧' end
    def msg_recent_changes; '更新履歴' end
    def msg_newpage; '新規' end
    def msg_no_recent; '<P>更新情報が存在しません。</P>' end
    def msg_thanks; '更新ありがとうございました。' end
    def msg_save_conflict; '更新が衝突しました。下記の内容をテキストエディタなどに保存し、最新のページを参照後に再編集してください。' end
    def msg_time_format; "%Y-%m-%d #DAY# %H:%M:%S" end
    def msg_date_format; "%Y-%m-%d " end
    def msg_day; %w(日 月 火 水 木 金 土) end
    def msg_preview; '以下のプレビューを確認し、問題がなければページの下にある保存ボタンで保存してください →<a href="#form">編集フォーム</a>' end
    def msg_mail_on; 'メールで通知' end
    def msg_mail_off; '非通知' end
    def msg_use; '使用する' end
    def msg_unuse; '使用しない' end
    def msg_login_info; '管理者としてログインする際は、ユーザ名に admin と入力してください。' end
    def msg_login_failure; 'ユーザ名またはパスワードが間違っています。' end
    def msg_name; 'ユーザ名' end
    def msg_password; 'パスワード' end
    def msg_ok; 'OK' end
    def msg_invalid_password; 'パスワードが間違っています。まだ設定情報は保存されていません。' end
    def msg_save_config; '設定を保存しました。' end
    def msg_freeze; 'このページは凍結されています。保存には管理者用のパスワードが必要です。' end
    def msg_freeze_mark; '【凍結】' end
    def msg_already_exist; '指定のページはすでに存在しています。' end
    def msg_page_not_exist; '指定のページは存在しません。ぜひ、作成してください:-)' end
    def msg_invalid_filename(s); "不正な文字が含まれているか、最大長(#{s}バイト)を超えています。ページ名を修正してください。" end
    def msg_delete; 'ページを削除しました' end
    def msg_delete_page; '以下のページを削除しました。' end
    def msg_follow_link; '以下のリンクをたどってください: ' end
    def msg_match_title; '[タイトルに一致]' end
    def msg_match_keyword; '[キーワードに一致]' end
    def msg_duplicate_page_title; '指定したタイトルは既に存在しています。' end
    def msg_missing_anchor_title; 'ページ %s を新規作成し、編集します。' end
    def msg_unbalanced_paren; '括弧の数が合っていません.' end
    # (config)
    def msg_config; 'Hiki 環境設定'; end
    # (diff)
    def msg_diff_add; '最後の更新で追加された部分は<ins class="added">このように</ins>表示します。'; end
    def msg_diff_del; '最後の更新で削除された部分は<del class="deleted">このように</del>表示します。'; end
    # (edit)
    def msg_description; '説明'; end
    def msg_funcname; '関数名'; end
    def msg_funcarg; '引数名'; end
    def msg_funcbody; '関数本体'; end
    def msg_require_test; '必要な関数とテストケース'; end
    def msg_freeze_checkbox; 'ページの凍結'; end
    def msg_preview_button; 'プレビュー'; end
    def msg_require_button; 'Require'; end
    def msg_save; '保存'; end
    def msg_cancel; 'キャンセル'; end
    def msg_update_timestamp; 'タイムスタンプを更新する'; end
    def msg_latest; '最新版を参照'; end
    def msg_rules; %Q|書き方がわからない場合は<a href="#{@cgi_name}?TextFormattingRules">TextFormattingRules</a>を参照してください。|; end
    # (view)
    def msg_last_modified; '更新日時'; end
    def msg_keyword; 'キーワード'; end
    def msg_reference; '参照'; end
    def msg_input_is_spam; '入力されたデータをスパムと判定しました。'; end
    # (apply)
    def msg_modified_newer; '%sより後に変更された関数:'; end
  end
end
