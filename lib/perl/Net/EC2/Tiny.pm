package Net::EC2::Tiny;

use 5.014;

use POSIX qw(strftime);
use URI;
use URI::Escape qw(uri_escape_utf8);
use Digest::SHA qw(hmac_sha256);
use MIME::Base64 qw(encode_base64);
use XML::Simple qw(XMLin);
use HTTP::Tiny;

use Moo;

has 'AWSAccessKey'       => ( is => 'ro', required => 1 );
has 'AWSSecretKey'       => ( is => 'ro', required => 1 );
has 'debug'              => ( is => 'ro', required => 0, default => sub { 0 } );
has 'signature_version'  => ( is => 'ro', required => 1, default => sub { 2 } );
has 'version'            => ( is => 'ro', required => 1, default => sub { '2012-07-20' } );
has 'region'             => ( is => 'ro', required => 1, default => sub { 'us-east-1' } );
has 'base_url'           => ( 
    is          => 'ro', 
    required    => 1,
    lazy        => 1,
    default     => sub {
        'https://' . $_[0]->region . '.ec2.amazonaws.com';
    }
);
has 'ua'                 => (
    is          => 'ro',
    required    => 1,
    lazy        => 1,
    default     => sub {
        HTTP::Tiny->new(
            'agent' => 'Net::EC2::Tiny ',
        );
    }
);

sub _timestamp {
    return strftime("%Y-%m-%dT%H:%M:%SZ",gmtime);
}
    
sub _sign {
    my $self                        = shift;
    my %args                        = @_;
    my $action                      = delete $args{Action};
    my %sign_hash                   = %args;
    my $timestamp                   = $self->_timestamp;

    $sign_hash{AWSAccessKey}        = $self->AWSAccessKey;
    $sign_hash{Action}              = $action;
    $sign_hash{Timestamp}           = $timestamp;
    $sign_hash{Version}             = $self->version;
    $sign_hash{SignatureVersion}    = $self->signature_version;
    $sign_hash{SignatureMethod}     = "HmacSHA256";

    my $sign_this = "POST\n";
    my $uri = URI->new($self->base_url);

    $sign_this .= lc($uri->host) . "\n";
    $sign_this .= "/\n";

    my @signing_elements;

    foreach my $key (sort keys %sign_hash) {
        push @signing_elements, uri_escape_utf8($key)."=".uri_escape_utf8($sign_hash{$key});
    }

    $sign_this .= join "&", @signing_elements;

    warn "QUERY TO SIGN: $sign_this" if $self->debug;
    my $encoded = $self->_hashit($self->AWSSecretKey, $sign_this);

    my %params = (
        Action                => $action,
        SignatureVersion      => "2",
        SignatureMethod       => "HmacSHA256",
        AWSAccessKeyId        => $self->AWSAccessKey,
        Timestamp             => $timestamp,
        Version               => $self->version,
        Signature             => $encoded,
        %args
    );
    
    my $ur    = $uri->as_string();
    warn "GENERATED QUERY URL: $ur" if $self->debug;

    return $self->ua->post($uri, \%params);

}

sub send {
    my $self = shift;

    my $response = $self->_sign(@_);

    if ( $response->{success} ) {
        return XMLin($response->{content}, 
                ForceArray    => qr/(?:item|Errors)/i,
                KeyAttr       => '',
                SuppressEmpty => undef,
        );
    }
    else {
        die "POST Request failed: $response->{status} $response->{content}\n";
    }
}

sub _hashit {
    my $self                               = shift;
    my ($secret_access_key, $query_string) = @_;
    
    return encode_base64(hmac_sha256($query_string, $secret_access_key), '');
}


1;
