#!/usr/bin/env perl

use strict;
use warnings;

use Test::Spec;
use File::Basename;
use File::Spec;
use Crypt::File qw(crypt_file);
use Try::Tiny;

my $dir = dirname( __FILE__  ) . '/../lib';

describe 'crypt_file' => sub {
    it 'should die when not called in eval' => sub {
        my $cmd = "$^X -I$dir -MCrypt::File=crypt_file -e 'crypt_file()'";
        my $qx = qx{$cmd 2>&1};
    
        like $qx, qr~Sorry, it's necessary to catch exceptions to ensure an stable processing! Please use try/catch!~;
    };

    it 'only accepts "d" and "e" as mode' => sub {
        my %testmodes = (
            d    => 1,
            e    => 1,
            ''   => 0,
            'de' => 0,
            1    => 0,
            []   => 0,
        );

        for my $mode ( undef, sort keys %testmodes ) {
            my $error = '';
            try {
                crypt_file( crypt_mode => $mode );
            }
            catch {
                $error = $_;
            };

            if ( !defined $mode || !$testmodes{$mode} ) {
                like $error, qr/is not a valid crypt mode. Valid crypt mode are/, ($mode // '<undef>') . 'is not valid';
            }
            else {
                unlike $error, qr/is not a valid crypt mode. Valid crypt mode are/, "check mode $mode";
            }
        }
    };

    it 'needs a file' => sub {
        for my $mode ( qw/d e/ ) {
            my $error = '';
            try {
                crypt_file( crypt_mode => $mode );
            }
            catch {
                $error = $_;
            };

            like $error, qr/You have to specify a file./;
        }
    };

    it 'needs a valid cipher' => sub {
        my %testciphers = (
            d     => 0,
            e     => 0,
            ''    => 0,
            'de'  => 0,
            1     => 0,
            []    => 0,
            'aes' => 0,
            'AES' => 1,
        );

        my $file = File::Spec->catfile(
            dirname( __FILE__ ),
            'test.txt'
        );

        for my $cipher ( undef, sort keys %testciphers ) {
            my $error = '';
            try {
                crypt_file(
                    crypt_mode => 'd',
                    file       => $file,
                    cipher     => $cipher,
                    iv         => 256,
                );
            }
            catch {
                $error = $_;
            };

            if ( !defined $cipher || $testciphers{$cipher} ) {
                unlike $error, qr/is not a valid cipher. Valid ciphers are/, "check cipher $cipher";
            }
            else {
                like $error, qr/is not a valid cipher. Valid ciphers are/, ($cipher // '<undef>') . 'is not valid';
            }
        }
    };
};

runtests unless caller;
