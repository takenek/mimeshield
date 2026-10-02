-- MIME Shield (mimeshield) - database schema for MySQL / MariaDB
-- Install:  bin/initdb.sh --dir=plugins/mimeshield/SQL
-- Update:   bin/updatedb.sh --package=mimeshield --dir=plugins/mimeshield/SQL
-- Table names are prefixed automatically with $config['db_prefix'] by Roundcube.

SET FOREIGN_KEY_CHECKS=0;

-- User's own certificates with private keys (keys are AEAD-encrypted with the installation master key)
CREATE TABLE `mimeshield_keys` (
 `key_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
 `user_id` int(10) UNSIGNED NOT NULL,
 `fingerprint` varchar(64) NOT NULL,
 `serial` varchar(128) NOT NULL DEFAULT '',
 `subject` text NOT NULL,
 `issuer` text NOT NULL,
 `emails` text NOT NULL,
 `not_before` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 `not_after` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 `cert_pem` longtext NOT NULL,
 `chain_pem` longtext NOT NULL,
 `key_blob` longtext NOT NULL,
 `key_kid` varchar(16) NOT NULL,
 `key_format` smallint NOT NULL DEFAULT '1',
 `key_type` varchar(16) NOT NULL DEFAULT '',
 `key_bits` int(10) UNSIGNED NOT NULL DEFAULT '0',
 `created` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 `changed` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 PRIMARY KEY (`key_id`),
 UNIQUE `mimeshield_keys_user_fp` (`user_id`, `fingerprint`),
 CONSTRAINT `mimeshield_keys_user_id_fk` FOREIGN KEY (`user_id`)
   REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=INNODB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Which key signs for which Roundcube identity
CREATE TABLE `mimeshield_bindings` (
 `user_id` int(10) UNSIGNED NOT NULL,
 `identity_id` int(10) UNSIGNED NOT NULL,
 `key_id` int(10) UNSIGNED NOT NULL,
 `changed` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 PRIMARY KEY (`user_id`, `identity_id`),
 INDEX `mimeshield_bindings_key` (`key_id`),
 CONSTRAINT `mimeshield_bindings_user_id_fk` FOREIGN KEY (`user_id`)
   REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT `mimeshield_bindings_identity_id_fk` FOREIGN KEY (`identity_id`)
   REFERENCES `identities` (`identity_id`) ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT `mimeshield_bindings_key_id_fk` FOREIGN KEY (`key_id`)
   REFERENCES `mimeshield_keys` (`key_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=INNODB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Public certificates of correspondents (recipient store)
CREATE TABLE `mimeshield_certs` (
 `cert_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
 `user_id` int(10) UNSIGNED NOT NULL,
 `fingerprint` varchar(64) NOT NULL,
 `serial` varchar(128) NOT NULL DEFAULT '',
 `subject` text NOT NULL,
 `issuer` text NOT NULL,
 `emails` text NOT NULL,
 `not_before` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 `not_after` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 `cert_pem` longtext NOT NULL,
 `chain_pem` longtext NOT NULL,
 `source` varchar(16) NOT NULL DEFAULT 'import',
 `trust` varchar(16) NOT NULL DEFAULT 'observed',
 `created` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 `changed` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
 PRIMARY KEY (`cert_id`),
 UNIQUE `mimeshield_certs_user_fp` (`user_id`, `fingerprint`),
 CONSTRAINT `mimeshield_certs_user_id_fk` FOREIGN KEY (`user_id`)
   REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=INNODB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- E-mail address index of the recipient store (one row per address of a certificate)
CREATE TABLE `mimeshield_cert_emails` (
 `user_id` int(10) UNSIGNED NOT NULL,
 `cert_id` int(10) UNSIGNED NOT NULL,
 `email` varchar(255) NOT NULL,
 `preferred` tinyint(1) NOT NULL DEFAULT '0',
 PRIMARY KEY (`cert_id`, `email`),
 INDEX `mimeshield_cert_emails_lookup` (`user_id`, `email`),
 CONSTRAINT `mimeshield_cert_emails_user_id_fk` FOREIGN KEY (`user_id`)
   REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT `mimeshield_cert_emails_cert_id_fk` FOREIGN KEY (`cert_id`)
   REFERENCES `mimeshield_certs` (`cert_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=INNODB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS=1;

INSERT INTO `system` (`name`, `value`) VALUES ('mimeshield-version', '2026100200');
