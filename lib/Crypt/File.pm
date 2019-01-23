package Crypt::File;

# ABSTRACT: provide functions for symmetric decryption and encryption of file

use strict;
use warnings;
use v5.10;

use utf8;
use Crypt::Mode::CBC;

use Crypt::Mac::HMAC qw( hmac_hex );
use Crypt::Digest::SHA256 qw( sha256);
use Test::File::Contents;

use Exporter 'import';
our @EXPORT_OK = qw(crypt_file get_encrypted_file_content);

use Carp;
use Data::Dumper;

our $VERSION = 1.01;

=encoding utf8

=head1 Crypt:File.pm

=head1 BESCHREIBUNG

Modul stellt Funktionen für die symetrische Ver- und Entschlüsselung von Dateien
bereit und generiert/validiert einen MAC für die Authenzität- und Integritätssicherung.
Das Chifrat und die MAC werden als neue Dateien mit entsprechender Endung in dem Ordner
des Plaintext Files abgelegt.

Beispiel: Im Ordner Ordner01 liegt die Datei plaintext.txt

Nach der Verschlüsselung liegen in dem Ordner
- plaintext.txt
- plaintext.txt.enc
- plaintext.txt.hmac

Nach erneuter Entschlüsselung kommt die Datei: plaintext.txt.dec hinzu oder durch
die Option only_return_string => 1 erhält man Plaintext als string.

Die Verschlüsselung basiert auf dem CPAN Modul CryptX.

Es werden folgende kryptografische Verfahren  genutzt:
 - Symetrischer Cipher: AES,
 - MAC: HMAC
 - Kryptografische Hash Funktion zur Erzeugung der passenden Schlüssellänge: SHA256

Bei nicht zulässigen Parametern oder I/O Exceptions gibt es ein die/croak.
 
=head1 ANWENDUNG

=head1 CHANGES
 
=over 4
 
=item 07.12.2018 FLS:   Modul v1.0
 
=back
 
=head1 METHODEN

Optionale Parameter
- hmac_key: Schlüssel zur Erzeugung des HMAC, sonst wird Default Schlüssel verwendet
- only_return_string: 1 nur zulässig bei decryption
- cipher: AES
 
=head2 get_encrypted_file_content

Convenience Funktion zur Entschlüsselung 

Obligatorische Übergabeparameter:
- file: Datei die verschlüsselt werden soll
- key: Schlüssel für symetrischen Cipher
- iv: Initialiesierungvektor

Optionale Parameter:
- hmac_key: Schlüssel zur Erzeugung des HMAC, sonst wird Default Schlüssel verwendet
- cipher: AES
 
=cut



# ----------------------
# ----------------------
 
=head2 crypt_file
 
=over 4
 
=item Beschreibung
 
Verschlüsselt (encrypt) oder entschlüsselt (decrypt) Dateien.
 
=item Aufruf
 
   my $r = crypt_file(
                  file               => <Datei>,          # zu entschlüsselnde Datei bei crypt_mode = 'd'   (decrypt)
                                                          # zu verschlüsselnde Datei bei crypt_mode = 'e'   (encrypt)
                                                          
                  # key , hmac_key und iv müssen bei entschlüsselung mit denen der Verschlüsselung übereinstimmen                                             
                  key                => <Schlüssel für Entschlüsselung>,
                  hmac_key           => <checkwert mit integrität und authentizität>,
                  iv                 => <initialisierungs-Vektor>,           # muss mit dem zur Verschlüsselung übereinstimmen ???
                  
                  cipher             => <Verschlüsselungsmethode z.B. AES>,
                  only_return_string => 1,
                  crypt_mode         => 'd'
    
            ) ;
            
 
Aufruf der Funktion crypt_file mit den folgenden Parametern:
Obligatorische Parameter:
- crypt_mode : 'd' oder 'e' für Decyrption oder Encryption
- file: Datei die verschlüsselt werden soll
- key: Schlüssel für symetrischen Cipher
- iv: Initialiesierungvektor

 
=item Parameter

=back
 
=over 4
 
=item par1
 
=item par2

=item Rückgabe

=back 

=cut

sub crypt_file {

    # Define parameters

    my %args = @_;
    
    # Exceptions have to be caught    
    unless($^S){
        croak("Sorry, it's necessary to catch exceptions to ensure an stable processing! Please use try/catch!");
    }

    #Crypt mode
    my $crypt_mode = $args{crypt_mode};

    my %valid_crypt_modes = (
        'd' => 1,    # decryption
        'e' => 1,    # encryption
    );
    

    unless ( $valid_crypt_modes{$crypt_mode} ) {

        croak( "$crypt_mode is not a valid crypt mode. Valid crypt mode are " . Dumper( keys %valid_crypt_modes ) );
        
    }

    # File
    my $file = $args{file};
    unless ($file) {
        croak "You have to specify a file.";
    }

    # Create an 128 Bits long key based on parameter key
    my $key = $args{key};
    my $key_length = 128 ;
    $key = substr( sha256($key), 0, $key_length );

    my $hmac_key = $args{key};
    $hmac_key //= 'abcdefghijklmnopqrstuvwxyzabcdef';
    $hmac_key = substr( sha256($hmac_key), 0, 128 );

    my $iv = $args{iv};

    # Set cipher
    # Only symetric ciphers with an 128 Bit can be used
    my %valid_cipher = (
        'AES' => 1,

    );

    my $cipher = $args{cipher};
    $cipher //= 'AES';

    unless ( $valid_cipher{$cipher} ) {
        croak( "$cipher is not a valid cipher. Valid ciphers are " . Dumper( keys %valid_cipher ) );
    }

    # Create cipher object
    my $m = Crypt::Mode::CBC->new($cipher);

    my $file_output;

    # Set output file and start de/encryptions
    if ( $crypt_mode eq 'e' ) {
        $file_output = $file . '.enc';

        $m->start_encrypt( $key, $iv );
    }
    elsif ( $crypt_mode eq 'd' ) {
        
        if ( substr( $file, -4 ) eq '.enc' ) {
            $file_output = substr( $file, 0, -4 ) . '.dec';
        }
        else {
            $file_output = $file . '.dec';
        }

        $m->start_decrypt( $key, $iv );
    }

    #------------------------------------------------------------------------------
    # en/decryption process with hmac
    #------------------------------------------------------------------------------

    open my $fh_in, '<', $file
        or croak($!);

    binmode($fh_in);

    # Generate HMAC and write it into file before encrypt
    if ( $crypt_mode eq 'e' ) {

        open my $fh_in_for_hmac, '<', $file
            or croak($!);

        binmode($fh_in_for_hmac);

        my $plaintext_string = do {
            local $/ = undef;
            open my $fh, "<", $file
                or croak( "could not open $file: $!");
            <$fh_in_for_hmac>;
        };

        close $fh_in_for_hmac
            or croak($!);

        my $hmac_hex = hmac_hex( 'SHA256', $hmac_key, $plaintext_string );

        open my $fh_hmac, '>', $file . '.hmac'
            or croak($!);

        binmode($fh_hmac);

        syswrite $fh_hmac, $hmac_hex;

        close $fh_hmac
            or croak($!);
    }

    # symetric block de- and encryption
    my $line;
    my $output = '';
    my $block_size = 128 ;

    while ( sysread( $fh_in, $line, $block_size ) ) {
        $output .= $m->add($line);
    }

    $output .= $m->finish;

    # Proove HMAC from file with decrypted text after decryption
    if ( $crypt_mode eq 'd' ) {

        # Proove HMAC
        my $hmac_hex_dec = hmac_hex( 'SHA256', $hmac_key, $output );

        my $hmac_file;

        if ( substr( $file, -4 ) eq '.enc' ) {
            $hmac_file = substr( $file, 0, -4 ) . '.hmac';
        }
        else {
            $hmac_file = $file . '.hmac';
        }

        open my $fh_hmac_in, '<', $hmac_file
            or croak($!);

        my $hmac_from_file = <$fh_hmac_in>;

        my $macs_are_equal = $hmac_from_file eq $hmac_hex_dec;

        unless ($macs_are_equal) {
            croak "HMAC are not equal! Decryption stopped.";
        }

        close $fh_hmac_in
            or croak($!);

    }

    close $fh_in
        or croak($!);

    # Output Option string for decryption

    if ( $args{only_return_string} && $crypt_mode eq 'd' ) {
        return $output;
    }

    # Default Output
    open my $fh_out, '>', $file_output
        or croak($!);

    binmode($fh_out);

    $\ = undef;
    print $fh_out $output;

    close $fh_out
        or croak($!);

}

#Convenience function

sub get_encrypted_file_content {

    # Parameters
    my %args = @_;

    # Call decryption
    crypt_file(
        file               => $args{file},
        key                => $args{key},
        hmac_key           => $args{hmac_key},
        iv                 => $args{iv},
        cipher             => $args{cipher},
        only_return_string => 1,
        crypt_mode         => 'd'
    );

}

1;
