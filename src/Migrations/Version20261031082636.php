<?php

declare(strict_types=1);

namespace App\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20261031082636 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create vault and credential tables with UUIDv7 primary keys and cascading foreign key relations.';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE credential (id UUID NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, title VARCHAR(200) NOT NULL, encrypted_password TEXT NOT NULL, username VARCHAR(255) DEFAULT NULL, url VARCHAR(2048) DEFAULT NULL, encrypted_notes TEXT DEFAULT NULL, vault_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX idx_credential_vault ON credential (vault_id)');
        $this->addSql('CREATE TABLE vault (id UUID NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, name VARCHAR(150) NOT NULL, description TEXT DEFAULT NULL, owner_id INT NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX idx_vault_owner ON vault (owner_id)');
        $this->addSql('ALTER TABLE credential ADD CONSTRAINT FK_57F1D4B58AC2DF8 FOREIGN KEY (vault_id) REFERENCES vault (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE vault ADD CONSTRAINT FK_FF3049217E3C61F9 FOREIGN KEY (owner_id) REFERENCES "user" (id) ON DELETE CASCADE NOT DEFERRABLE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE credential DROP CONSTRAINT FK_57F1D4B58AC2DF8');
        $this->addSql('ALTER TABLE vault DROP CONSTRAINT FK_FF3049217E3C61F9');
        $this->addSql('DROP TABLE credential');
        $this->addSql('DROP TABLE vault');
    }
}
