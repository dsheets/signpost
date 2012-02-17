package signpost_transform;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(manage_key);  # symbols to export on request

use Net::DNS::RR;
use Net::DNS;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use Net::DNS::SEC::Private;

use strict;

sub construct_rsa_key {
    # Implementation using crypt::openssl                                                    
    my ($keyrr) = @_;                                   
    # RSA RFC2535                                                                            
    #                                                                                        

    my $explength;                                                                           
    my $exponent;                                                                            
    my $modulus;                                                                             
    my $RSAPublicKey;                                                                        

    {   #localise dummy                                                                      
        my $dummy=1;                                                                         
        # determine exponent length                                                          
        #RFC 2537 sect 2                                                                     
        ($dummy, $explength)=unpack("Cn",$keyrr->keybin)                                     
        if ! ($explength=unpack("C",$keyrr->keybin));                                    

        # We are constructing the exponent and modulus as a hex number so                    
        # the AUTOLOAD function in Crypt::RSA::Key::Public can deal with it                  
        # later, there must be better ways to do this,                                       
        if ($dummy) { # skip one octet                                                       
            $exponent=(substr ($keyrr->keybin, 1, $explength));                                                 
            $modulus=( substr ($keyrr->keybin,  1+$explength,                                    
                    (length $keyrr->keybin) - 1 - $explength));                                               
        }else{ # skip two octets                                                             
            $exponent=(substr ($keyrr->keybin,3, $explength));                                                 

            $modulus=( substr ($keyrr->keybin, 3+$explength,
                    (length $keyrr->keybin) - 3 - $explength));                                               
        }
    } 


    my $bn_modulus=Crypt::OpenSSL::Bignum->new_from_bin($modulus);
    my $bn_exponent=Crypt::OpenSSL::Bignum->new_from_bin($exponent);

    my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters($bn_modulus,$bn_exponent);

    die "Could not load public key" unless $rsa_pub;
    return $rsa_pub;                                         
}

sub transform_key {
    my $opt = shift;
    my @in_keys;

    my $dnskey;
    # load input key
    if ($opt->{"in_type"} eq "dns_pub") {
        if (exists($opt->{"in_key"})) {
            # right here code to parse an rsa public key
            open(FILE, $opt->{"in_key"}) or die("Fialed to open file " .
                $opt->{"in_key"});
            while(<FILE>) {
                if(! /^;/) {
                    print $_;
                    $dnskey = Net::DNS::RR->new($_);
                    last;
                }
            }
            my $in_key = construct_rsa_key($dnskey);
            print $in_key->get_public_key_string() . "\n";
            push \@in_keys, $in_key; 
        } elsif (exists($opt->{"in_name"})) {
            print "looking up name " . $opt->{"in_name"} . "\n";
            my $res = Net::DNS::Resolver->new(config_file => '/etc/resolv.conf');
            my $packet = $res->search($opt->{"in_name"}, 'DNSKEY');
            my @answer = $packet->answer;
            foreach my $rr (@answer) {
                if($rr->type eq "DNSKEY") {
                    my $in_key =  construct_rsa_key($rr);
                    print $in_key->get_public_key_string() . "\n";
                    push \@in_keys, $in_key;
                }
            }
        }
    } elsif ($opt->{"in_type"} eq "dns_priv") {
        if(exists($opt->{"in_key"})) {
            $in_key = Net::DNS::SEC::Private->new($opt->{"in_key"})->private;
            print $in_key->get_public_key_string();
            push \@in_keys, $in_key;
        }
    }
    return 1;
}

sub manage_key {
    my $opt = shift;

    if($opt->{"action"} eq "sign") {
        print "signing input key\n";
        print "not implemented yet\n";
    } elsif ($opt->{"action"} eq "transform") {
        print "transform input to output type\n";
        return transform_key($opt);
    } elsif ($opt->{"action"} eq "verify") {
        print "verify input certificate is signed by ca public key\n";
        print "not implemented yet\n";
    } else {
        print "Invalid action, aborting\n";
        return 0;
    }
}

return 1; 
