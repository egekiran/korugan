<?php

declare(strict_types=1);

namespace App\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20261031085120 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add totp_secret and is_totp_enabled columns to the user table for TOTP two-factor authentication.';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE "user" ADD totp_secret VARCHAR(255) DEFAULT NULL');
        $this->addSql('ALTER TABLE "user" ADD is_totp_enabled BOOLEAN DEFAULT false NOT NULL');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE "user" DROP totp_secret');
        $this->addSql('ALTER TABLE "user" DROP is_totp_enabled');
    }
}
