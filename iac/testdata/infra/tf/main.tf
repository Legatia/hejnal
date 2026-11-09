resource "aws_security_group" "bastion" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "internal" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }
}

resource "aws_vpc_security_group_ingress_rule" "all" {
  security_group_id = aws_security_group.internal.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_db_instance" "replica" {
  publicly_accessible = var.public
}

data "aws_iam_policy_document" "ci" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = "x"
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}
POLICY
}

resource "google_compute_firewall" "rdp" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["3389", "8000-8080"]
  }
}

resource "azurerm_network_security_group" "nsg" {
  security_rule {
    direction                  = "Inbound"
    access                     = "Allow"
    source_address_prefix      = "*"
    destination_port_range     = "6379"
    protocol                   = "Tcp"
  }
}

resource "google_storage_bucket_iam_member" "pub" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
