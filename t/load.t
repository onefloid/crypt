#!/usr/bin/env perl

use strict;
use warnings;

use Test::Spec;

describe 'just using basic stuff' => sub {
    it 'the module should load' => sub {
        my $error = '';
        eval { require Crypt::File } or $error = $@;

        BAIL_OUT "Can't load module" if $error;

        is $error, '';
    };

    require Crypt::File;

    it 'should know some functions' => sub {
        can_ok 'Crypt::File', qw/crypt_file get_encrypted_file_content/;
    };
};

runtests unless caller;
