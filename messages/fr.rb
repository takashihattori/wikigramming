# $Id: fr.rb,v 1.15 2005-07-14 01:50:25 fdiary Exp $
# fr.rb
#
# Copyright (C) 2003 Laurent Sansonetti <laurent@datarescue.be>
# You can redistribute it and/or modify it under the terms of
# the Ruby's licence.
#
# Original file is ja.rb:
# Copyright (C) 2002-2003 TAKEUCHI Hitoshi <hitoshi@namaraii.com>
# You can redistribute it and/or modify it under the terms of
# the Ruby's licence.
#
module Hiki
  module Messages_fr
    def msg_recent; 'Modifications r�centes' end
    def msg_create; 'Cr�er' end
    def msg_diff; 'Diff�rences' end
    def msg_edit; 'Editer' end
    def msg_search; 'Chercher' end
    def msg_admin; 'Administration' end
    def msg_login; 'Login' end
    def msg_logout; 'Logout' end
    def msg_search_result; 'R�sultats de la recherche' end
    def msg_search_hits; '\'%1$s\': %3$d page(s) trouv�es dans %2$d pages.' end
    def msg_search_not_found; '\'%s\' introuvable.' end
    def msg_search_comment; 'Rechercher sur le site entier.  Ignore la casse.  Hiki renvoie les pages contenant tous les mots de votre requ�te.' end
    def msg_frontpage; 'Accueil' end
    def msg_hitory; 'Historique' end
    def msg_index; 'Index' end
    def msg_recent_changes; 'Changements' end
    def msg_newpage; 'Nouveau' end
    def msg_no_recent; '<P>Pas de donn�es.</P>' end
    def msg_thanks; 'Merci.' end
    def msg_save_conflict; 'Il y a eu des conflits lors de la mise-�-jour.  Vos modifications n\'ont pas �t� sauv�es.  Sauvez temporairement vos modifications dans un �diteur, rechargez la page et r�-essayez l\'�dition � nouveau.' end
    def msg_time_format; "%Y-%m-%d #DAY# %H:%M:%S" end
    def msg_date_format; "%Y-%m-%d " end
    def msg_day; %w(Dimanche Lundi Mardi Mercredi Jeudi Vendredi Samedi) end
    def msg_preview; 'Ceci est une pr�visualisation de la page.  Si tout est correct, veuillez confirmer en cliquant sur le bouton Sauver. -&gt;<a href="#form">Formulaire</a>' end
    def msg_mail_on; 'Envoyer un e-mail de notification' end
    def msg_mail_off; 'Ne pas envoyer un e-mail de notification' end
    def msg_use; 'Utiliser' end
    def msg_unuse; 'Ne pas utiliser' end
    def msg_login_info; '(TRANSLATE PLEASE) If you want to login as an administrator, type \'admin\' in the Name field.' end
    def msg_login_failure; '(TRANSLATE PLEASE) Wrong name or password.' end
    def msg_name; 'Nom' end
    def msg_password; 'Mot de passe' end
    def msg_ok; 'OK' end
    def msg_invalid_password; 'Mot de passe incorrect.  Vos modifications n\'ont pas encore �t� sauvegard�es.' end
    def msg_save_config; 'Modifications sauv�es' end
    def msg_freeze; 'Cette page est gel�e.  Vous avez besoin du mot de passe administrateur pour continuer.' end
    def msg_freeze_mark; '[Geler]' end
    def msg_already_exist; 'Cette page a existe d�j�.' end
    def msg_page_not_exist; 'Cette page n\'existe pas.  Veuillez la remplir par vous-m�me ;-)' end
    def msg_invalid_filename(s); "Caract�re invalide d�tect�, ou taille maximale d�pass�e (#{s} octets).  Veuillez choisir un nouveau titre pour la page." end
    def msg_delete; 'Supprim�.' end
    def msg_delete_page; 'Cette page est supprim�e.' end
    def msg_follow_link; 'Cliquez sur le lien ci-dessous pour afficher votre page: ' end
    def msg_match_title; '[correspondance dans le titre]' end
    def msg_match_keyword; '[correspondance dans un mot clef]' end
    def msg_duplicate_page_title; 'Une page portant le m�me nom existe d�j�.' end
    def msg_missing_anchor_title; 'Create new %s and edit.' end
    # (config)
    def msg_config; 'Configuration du Hiki'; end
    # (diff)
    def msg_diff_add; 'Les lignes ajout�es sont affich�es <ins class="added">comme ceci</ins>.'; end
    def msg_diff_del; 'Les lignes retir�es sont affich�es <del class="deleted">comme cela</del>.'; end
    # (edit)
    def msg_title; 'Titre de la page'; end
    def msg_keyword_form; 'Mot clef (veuillez entrer distinctement chaque mot sur une ligne � part)'; end
    def msg_freeze_checkbox; 'Geler la page courante.'; end
    def msg_preview_button; 'Pr�visualiser'; end
    def msg_save; 'Sauver'; end
    def msg_update_timestamp; '(TRANSLATE PLEASE) Update timestamp'; end
    def msg_latest; 'R�f�rencie version r�cente'; end
    def msg_rules; %Q|Consultez <a href="#{@cgi_name}?ReglesDeFormatageDuTexte">ReglesDeFormatageDuTexte</a> si n�cessaire.|; end
    # (view)
    def msg_last_modified; 'Derni�re modification'; end
    def msg_keyword; 'Mots clef'; end
    def msg_reference; 'R�f�rences'; end
  end
end
