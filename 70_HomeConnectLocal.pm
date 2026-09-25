########################################################################################
#
#  70_HomeConnectLocal.pm
#
#  FHEM module for local communication with Home Connect appliances
#  via the appliance LAN interface (TLS-PSK / AES / WebSocket).
#
#  Supported device classes currently include:
#    - Dishwasher
#    - Hob
#    - Washer / WasherDryer
#
#  Device capabilities, programs, settings and options are loaded dynamically
#  from external Home Connect DeviceDescription and FeatureMapping XML files.
#
#  Version 1.39, 25.09.2026
#  $Id: 70_HomeConnectLocal.pm 1.39 2026-09-25 $
#
########################################################################################
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  The GNU General Public License can be found at
#  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#  A copy is normally distributed with FHEM as GPL.txt.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
########################################################################################
#
#  Security notes:
#    - Cryptographic session keys and protocol state are kept outside the FHEM
#      device hash and therefore are not exposed as FHEMWEB Internals.
#    - Raw protocol readings are hidden by default. Set showRawReadings=1 only
#      temporarily for diagnostics because raw data can contain device/network
#      information.
#    - The encryptionKey attribute contains the appliance pairing key and must
#      be treated as confidential configuration data.
#
########################################################################################
#
#  Changelog
#
#  1.00      Initial local Home Connect connection using TLS-PSK/WebSocket
#  1.01      Dynamic loading of DeviceDescription/FeatureMapping XML files
#  1.02      Dynamic programs, settings and program options
#  1.03      Runtime metadata from /ro/allDescriptionChanges
#  1.04      Program start/stop and program-dependent options
#  1.05      Dynamic enum, boolean and slider SET commands
#  1.06      Runtime access/availability takes precedence over static XML data
#  1.07      Automatic FHEMWEB refresh when runtime SET capabilities change
#  1.08      Context refresh after program and option changes
#  1.20      FHEMWEB program preparation popup added
#  1.25      Popup synchronization using runtime revisions
#  1.29      Optional DE/EN display translation
#  1.33      Dishwasher-specific program option handling
#  1.34      Sensitive cryptographic Internals moved to private module storage;
#            raw protocol readings can be hidden
#  1.35      Logging policy cleaned up: level 2 important lifecycle events,
#            level 3 errors only, level 5 diagnostics/debug
#  1.36      Added module header, GPL notice and FHEM commandref documentation
#  1.37      Central module version added and exposed as MODULE_VERSION Internal
#  1.38      LastSetList Internal formatted with line breaks for FHEMWEB
#  1.39      LastSetList uses real newlines; long enum/program entries wrap at commas
#
########################################################################################

package main;

# Logging policy:
#   level 2 = important lifecycle events
#   level 3 = errors only
#   level 5 = diagnostics/debug

use strict;
use warnings;
use JSON::PP;
use IO::Socket::INET;
use MIME::Base64;
use Digest::SHA qw(hmac_sha256);
use Crypt::Mode::CBC;
use Encode qw(decode FB_CROAK);

# Private per-device protocol state. Kept outside the FHEM device hash so
# cryptographic session material is not exposed as FHEMWEB Internals.
my %HomeConnectLocal_Private;

# Central module version. Also exposed in each device as MODULE_VERSION.
my $HomeConnectLocal_VERSION = '1.39';


##############################################
# Initialize
##############################################

sub HomeConnectLocal_Initialize {
    my ($hash) = @_;

    $hash->{DefFn}   = "HomeConnectLocal_Define";
    $hash->{UndefFn} = "HomeConnectLocal_Undefine";
    $hash->{SetFn}   = "HomeConnectLocal_Set";
    $hash->{GetFn}   = "HomeConnectLocal_Get";
    $hash->{AttrFn}  = "HomeConnectLocal_Attr";
    $hash->{NotifyFn} = "HomeConnectLocal_Notify";
    $hash->{ReadFn}  = "HomeConnectLocal_Read";
    $hash->{FW_detailFn} = "HomeConnectLocal_FwDetail";
    # v21: keep the normal FHEMWEB device/state overview visible even with FW_detailFn.
    $hash->{FW_deviceOverview} = 1;

    no strict 'vars';
    $data{FWEXT}{HomeConnectLocal}{SCRIPT} = "HomeConnectLocal.js";

    $hash->{AttrList} =
          "disable:0,1 "
        . "encryptionKey "
        . "connectionType:TLS,AES "
        . "iv "
        . "deviceType:dishwasher,hob,washer,washerdryer "
        . "mappingDir "
        . "mappingPrefix "
        . "excludeReadings "
        . "showRawReadings:0,1 "
        . "excludeSets "
        . "translation:off,DE,EN "
        . "programPopup:on,off "
        . $main::readingFnAttributes;

    use strict 'vars';
}


##############################################
# Define
##############################################

sub HomeConnectLocal_Define {
    my ($hash, $def) = @_;

    my @a = split("[ \t]+", $def);

    return "Usage: define <name> HomeConnectLocal <IP>"
        if @a < 3;

    my ($name, $type, $host) = @a;

    $hash->{NAME} = $name;
    $hash->{Host} = $host;
    $hash->{MODULE_VERSION} = $HomeConnectLocal_VERSION;

    $hash->{DeviceID} ||= sprintf(
        "%08x",
        int(rand(4294967296))
    );

    $hash->{NOTIFYDEV} = "global";
    $hash->{STATE}   = "initialized";
    $hash->{PARTIAL} = "";

    Log3 $name, 5,
        "HomeConnectLocal ($name) - "
        . "Application DeviceID: $hash->{DeviceID}";

    Log3 $name, 5,
        "HomeConnectLocal ($name) - "
        . "Initialisiert für $host, "
        . "DeviceID=$hash->{DeviceID}";

    HomeConnectLocal_LoadMapping($hash);

    return undef;
}


##############################################
# Mapping Helpers
##############################################

sub HomeConnectLocal_NormalizeHex {
    my ($value) = @_;

    return ""
        if !defined $value;

    $value = "$value";

    $value =~ s/^\s+|\s+$//g;
    $value =~ s/^0x//i;

    return sprintf(
        "%04X",
        hex($value)
    ) if $value =~ /^[0-9A-Fa-f]+$/;

    return uc($value);
}


sub HomeConnectLocal_NormalizeProtocolUID {
    my ($value) = @_;

    return ""
        if !defined $value;

    $value = "$value";

    $value =~ s/^\s+|\s+$//g;

    return sprintf(
        "%04X",
        int($value)
    ) if $value =~ /^\d+$/;

    return sprintf(
        "%04X",
        hex($1)
    ) if $value =~ /^0x([0-9A-Fa-f]+)$/;

    return sprintf(
        "%04X",
        hex($value)
    ) if $value =~ /^[0-9A-Fa-f]{1,4}$/;

    return uc($value);
}


sub HomeConnectLocal_XmlDecode {
    my ($v) = @_;

    return ""
        if !defined $v;

    $v =~ s/&quot;/"/g;
    $v =~ s/&apos;/'/g;
    $v =~ s/&lt;/</g;
    $v =~ s/&gt;/>/g;
    $v =~ s/&amp;/&/g;
    $v =~ s/&#(\d+);/chr($1)/eg;
    $v =~ s/&#x([0-9A-Fa-f]+);/chr(hex($1))/eg;

    return $v;
}


sub HomeConnectLocal_ReadFile {
    my ($file) = @_;

    open(
        my $fh,
        "<",
        $file
    ) or return (
        undef,
        "Kann $file nicht öffnen: $!"
    );

    local $/;

    my $c = <$fh>;

    close($fh);

    return (
        $c,
        undef
    );
}


##############################################
# Mapping Files
##############################################

sub HomeConnectLocal_FindMappingPair {
    my ($hash) = @_;

    my $name = $hash->{NAME};

    my $dir = AttrVal(
        $name,
        "mappingDir",
        "/opt/fhem/FHEM/FHEM_HomeConnectLocal"
    );

    my $wanted = AttrVal(
        $name,
        "mappingPrefix",
        ""
    );

    opendir(
        my $dh,
        $dir
    ) or return (
        undef,
        undef,
        undef,
        "Mapping-Verzeichnis $dir kann nicht geöffnet werden: $!"
    );

    my @ff =
        sort
        grep {
            /_FeatureMapping\.xml$/i &&
            -f "$dir/$_"
        }
        readdir($dh);

    closedir($dh);

    if ($wanted ne "") {

        @ff = grep {
            /^\Q$wanted\E_FeatureMapping\.xml$/i
        } @ff;
    }

    return (
        undef,
        undef,
        undef,
        "Keine *_FeatureMapping.xml in $dir gefunden."
    ) if !@ff;

    my @pairs;

    for my $f (@ff) {

        (my $p = $f) =~
            s/_FeatureMapping\.xml$//i;

        my $d =
            $p . "_DeviceDescription.xml";

        if (-f "$dir/$d") {

            push @pairs, {
                prefix  => $p,
                feature => "$dir/$f",
                device  => "$dir/$d"
            };
        }
    }

    return (
        undef,
        undef,
        undef,
        "Keine zusammengehörigen Mapping-Dateien in $dir gefunden."
    ) if !@pairs;


    #
    # Bei mehreren Dateien anhand deviceType suchen.
    #
    if (
        @pairs > 1 &&
        $wanted eq ""
    ) {

        my $dt = lc(
            AttrVal(
                $name,
                "deviceType",
                ""
            )
        );

        if ($dt ne "") {

            my @m;

            for my $p (@pairs) {

                my ($x, $e) =
                    HomeConnectLocal_ReadFile(
                        $p->{device}
                    );

                next
                    if $e;

                if (
                    $x =~
                    m{
                        <description\b[^>]*>
                        .*?
                        <type>\s*([^<]+?)\s*</type>
                        .*?
                        </description>
                    }isx
                ) {

                    push @m, $p
                        if lc(
                            HomeConnectLocal_XmlDecode($1)
                        ) eq $dt;
                }
            }

            @pairs = @m
                if @m == 1;
        }
    }


    if (
        @pairs > 1 &&
        $wanted eq ""
    ) {

        return (
            undef,
            undef,
            undef,
            "Mehrere Mapping-Dateipaare gefunden: "
            . join(
                ", ",
                map {
                    $_->{prefix}
                } @pairs
            )
            . ". Bitte attr $name mappingPrefix <Prefix> setzen."
        );
    }


    return (
        $pairs[0]{prefix},
        $pairs[0]{device},
        $pairs[0]{feature},
        undef
    );
}


##############################################
# Load Mapping
##############################################

sub HomeConnectLocal_LoadMapping {
    my ($hash) = @_;

    my $name =
        $hash->{NAME};

    my (
        $prefix,
        $df,
        $ff,
        $err
    ) =
        HomeConnectLocal_FindMappingPair(
            $hash
        );

    if ($err) {

        Log3 $name, 3,
            "HomeConnectLocal ($name) - "
            . "XML Mapping: $err";

        $hash->{MappingLoaded} = 0;
        $hash->{MappingError}  = $err;

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "mapping_state",
            "error",
            1
        );

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "mapping_error",
            $err,
            1
        );

        return;
    }


    my ($dx, $de) =
        HomeConnectLocal_ReadFile(
            $df
        );

    my ($fx, $fe) =
        HomeConnectLocal_ReadFile(
            $ff
        );

    if (
        $de ||
        $fe
    ) {

        my $e =
            $de || $fe;

        Log3 $name, 3,
            "HomeConnectLocal ($name) - "
            . "XML Mapping: $e";

        $hash->{MappingLoaded} = 0;
        $hash->{MappingError}  = $e;
        delete $hash->{Mapping};

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "mapping_state",
            "error",
            1
        );

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "mapping_error",
            $e,
            1
        );

        return;
    }


    my (
        %fbu,
        %ubf,
        %ek,
        %ev,
        %etu,
        %meta,
        %ebe,
        %program_options,
        %program_option_meta
    );


    #
    # Features
    #
    while (
        $fx =~
        m{
            <feature\b
            [^>]*
            \brefUID="([^"]+)"
            [^>]*>
            \s*([^<]+?)\s*
            </feature>
        }gisx
    ) {

        my $u =
            HomeConnectLocal_NormalizeHex(
                $1
            );

        my $f =
            HomeConnectLocal_XmlDecode(
                $2
            );

        $fbu{$u} = $f;
        $ubf{$f} = $u;
    }


    #
    # Errors
    #
    while (
        $fx =~
        m{
            <error\b
            [^>]*
            \brefEID="([^"]+)"
            [^>]*>
            \s*([^<]+?)\s*
            </error>
        }gisx
    ) {

        $ebe{
            HomeConnectLocal_NormalizeHex(
                $1
            )
        } =
            HomeConnectLocal_XmlDecode(
                $2
            );
    }


    #
    # Enums
    #
    while (
        $fx =~
        m{
            <enumDescription\b([^>]*)>
            (.*?)
            </enumDescription>
        }gisx
    ) {

        my ($a, $b) =
            ($1, $2);

        my ($en) =
            $a =~
            /\brefENID="([^"]+)"/i;

        my ($key) =
            $a =~
            /\benumKey="([^"]+)"/i;

        next
            if !defined($en) ||
               !defined($key);

        $en =
            HomeConnectLocal_NormalizeHex(
                $en
            );

        $ek{$en} =
            HomeConnectLocal_XmlDecode(
                $key
            );

        while (
            $b =~
            m{
                <enumMember\b
                [^>]*
                \brefValue="([^"]+)"
                [^>]*>
                \s*([^<]*?)\s*
                </enumMember>
            }gisx
        ) {

            $ev{$en}{
                HomeConnectLocal_XmlDecode(
                    $1
                )
            } =
                HomeConnectLocal_XmlDecode(
                    $2
                );
        }
    }


    #
    # DeviceDescription enum subsets.
    #
    # Home Connect may announce a program-specific enumerationType at
    # runtime (for example 8021 for Temperature, 8029 for SpinSpeed or
    # 8B04 for DryingTarget).  Those subset ENIDs are defined only in the
    # DeviceDescription.xml and reference the base enum from the
    # FeatureMapping.xml via subsetOf.  Copy the labels for the listed
    # numeric values so FHEMWEB can render a dropdown instead of a slider.
    #
    while (
        $dx =~
        m{
            <enumerationType\b([^>]*)>
            (.*?)
            </enumerationType>
        }gisx
    ) {
        my ($ea, $eb) = ($1, $2);
        my ($enid) = $ea =~ /\benid="([^"]+)"/i;
        my ($base) = $ea =~ /\bsubsetOf="([^"]+)"/i;
        next if !defined($enid) || !defined($base);

        $enid = HomeConnectLocal_NormalizeHex($enid);
        $base = HomeConnectLocal_NormalizeHex($base);
        next if ref($ev{$base}) ne 'HASH';

        $ek{$enid} = $ek{$base} if defined($ek{$base});

        while ($eb =~ /<enumeration\b[^>]*\bvalue="([^"]+)"[^>]*\/?\s*>/gis) {
            my $v = HomeConnectLocal_XmlDecode($1);
            $ev{$enid}{$v} = $ev{$base}{$v}
                if exists($ev{$base}{$v});
        }
    }


    #
    # DeviceDescription-Metadaten je UID
    #
    # Die Attribute werden generisch aus status/setting/event/option
    # sowie activeProgram/selectedProgram gelesen. Dadurch koennen
    # spaetere Auswertungen (Enums, Zonen, initValue, min/max, stepSize
    # usw.) aus den XML-Dateien abgeleitet werden, ohne Geraetetabellen
    # im Perl-Modul zu pflegen.
    #
    while (
        $dx =~
        m{
            <(status|setting|event|option|command|program|activeProgram|selectedProgram)\b
            ([^>]*)
            >
        }gisx
    ) {

        my ($kind, $a) = ($1, $2);

        my ($u) =
            $a =~ /\buid="([^"]+)"/i;

        next if !defined($u);

        my $nu =
            HomeConnectLocal_NormalizeHex($u);

        $meta{$nu}{kind} = $kind;

        while (
            $a =~ /\b([A-Za-z][A-Za-z0-9_]*)="([^"]*)"/g
        ) {
            my ($k, $v) = ($1, HomeConnectLocal_XmlDecode($2));
            $meta{$nu}{$k} = $v;
        }

        if (defined($meta{$nu}{enumerationType})) {
            $etu{$nu} =
                HomeConnectLocal_NormalizeHex(
                    $meta{$nu}{enumerationType}
                );
        }
    }


    #
    # Program -> writable option associations.
    # Options inside <program> use refUID rather than uid, so they are not
    # covered by the generic metadata loop above.
    #
    while (
        $dx =~
        m{
            <program\b([^>]*)>
            (.*?)
            </program>
        }gisx
    ) {
        my ($pa, $pb) = ($1, $2);
        my ($pu) = $pa =~ /\buid="([^"]+)"/i;
        next if !defined($pu);

        my $npu = HomeConnectLocal_NormalizeHex($pu);
        my @opts;
        my %optmeta;

        while (
            $pb =~
            m{
                <option\b([^>]*)/?>
            }gisx
        ) {
            my $oa = $1;
            my ($ru) = $oa =~ /\brefUID="([^"]+)"/i;
            next if !defined($ru);

            my ($access) = $oa =~ /\baccess="([^"]+)"/i;
            next if defined($access) && $access ne 'readWrite' && $access ne 'writeOnly';

            my $nru = HomeConnectLocal_NormalizeHex($ru);
            push @opts, $nru;

            # Preserve the metadata declared on the option reference inside
            # this concrete program.  These attributes are program-context
            # capability data and must not be flattened into the global UID
            # metadata.
            my %pom;
            while ($oa =~ /\b([A-Za-z][A-Za-z0-9_]*)="([^"]*)"/g) {
                my ($k, $v) = ($1, HomeConnectLocal_XmlDecode($2));
                next if lc($k) eq 'refuid';
                $pom{$k} = $v;
            }
            $optmeta{$nru} = \%pom if %pom;
        }

        $program_options{$npu} = \@opts;
        $program_option_meta{$npu} = \%optmeta;
    }


    #
    # Device Info
    #
    my %di;

    if (
        $dx =~
        m{
            <description\b[^>]*>
            (.*?)
            </description>
        }isx
    ) {

        my $d =
            $1;

        for my $f (
            qw(
                type
                brand
                model
                version
                revision
            )
        ) {

            if (
                $d =~
                m{
                    <$f>
                    \s*([^<]*?)\s*
                    </$f>
                }isx
            ) {

                $di{$f} =
                    HomeConnectLocal_XmlDecode(
                        $1
                    );
            }
        }
    }


    $hash->{Mapping} = {
        FeatureByUID  => \%fbu,
        UIDByFeature  => \%ubf,
        EnumKeyByENID => \%ek,
        EnumValues    => \%ev,
        EnumTypeByUID => \%etu,
        MetaByUID     => \%meta,
        ProgramOptions => \%program_options,
        ProgramOptionMeta => \%program_option_meta,
        ErrorByEID    => \%ebe,
        DeviceInfo    => \%di
    };


    $hash->{MappingPrefix} =
        $prefix;

    $hash->{MappingDeviceFile} =
        $df;

    $hash->{MappingFeatureFile} =
        $ff;

    $hash->{MappingLoaded} =
        1;

    HomeConnectLocal_BuildSetMap($hash);

    delete
        $hash->{MappingError};


    if (
        exists
        $hash->{READINGS}{mapping_error}
    ) {

        readingsDelete(
            $hash,
            "mapping_error"
        );
    }


    Log3 $name, 2,
        "HomeConnectLocal ($name) - "
        . "XML Mapping geladen: "
        . "Prefix=$prefix, "
        . "Features="
        . scalar(keys %fbu)
        . ", Enums="
        . scalar(keys %ek)
        . ", Enum-UIDs="
        . scalar(keys %etu);


    readingsBeginUpdate(
        $hash
    );

    HomeConnectLocal_ReadingsBulkUpdate(
        $hash,
        "mapping_state",
        "loaded"
    );

    HomeConnectLocal_ReadingsBulkUpdate(
        $hash,
        "mapping_prefix",
        $prefix
    );

    HomeConnectLocal_ReadingsBulkUpdate(
        $hash,
        "mapping_features",
        scalar(keys %fbu)
    );

    HomeConnectLocal_ReadingsBulkUpdate(
        $hash,
        "mapping_enums",
        scalar(keys %ek)
    );


    for my $f (
        qw(
            type
            brand
            model
            version
            revision
        )
    ) {

        HomeConnectLocal_ReadingsBulkUpdate(
            $hash,
            "mapping_$f",
            $di{$f}
        ) if exists
            $di{$f};
    }


    readingsEndUpdate(
        $hash,
        1
    );

    return 1;
}


##############################################
# Runtime metadata from /ro/allDescriptionChanges
##############################################

sub HomeConnectLocal_ParseDescriptionChanges {
    my ($hash, $payload) = @_;
    return if !$hash;

    # The protocol handler passes the complete Home Connect message here.
    # Accept a bare data array as well so the helper remains reusable.
    my $data;
    if (ref($payload) eq 'HASH') {
        $data = $payload->{data};
    } elsif (ref($payload) eq 'ARRAY') {
        $data = $payload;
    }
    return if ref($data) ne 'ARRAY';

    $hash->{RuntimeMeta} ||= {};
    my $m = $hash->{Mapping};
    my $changed = 0;

    for my $item (@$data) {
        next if ref($item) ne 'HASH' || !defined($item->{uid});

        my $uid_num = $item->{uid};
        next if $uid_num !~ /^\d+$/;
        my $uid = sprintf('%04X', $uid_num);

        my $parent_num = $item->{parentUID};
        my $parent_uid = (defined($parent_num) && $parent_num =~ /^\d+$/)
            ? sprintf('%04X', $parent_num) : undef;

        my $bucket;
        if (defined($parent_uid)) {
            $hash->{RuntimeMeta}{$uid}{parents}{$parent_uid} ||= {};
            $bucket = $hash->{RuntimeMeta}{$uid}{parents}{$parent_uid};
        } else {
            $hash->{RuntimeMeta}{$uid}{global} ||= {};
            $bucket = $hash->{RuntimeMeta}{$uid}{global};
        }

        # Runtime description fields which can override the static XML data.
        for my $key (qw(access available default execution min max stepSize)) {
            $bucket->{$key} = $item->{$key} if exists($item->{$key});
        }

        # enumType is transmitted as a decimal UID. Store it in the same
        # canonical hexadecimal form used by the XML mapping.
        if (exists($item->{enumType})) {
            my $enum = $item->{enumType};
            $bucket->{enumType} =
                (defined($enum) && $enum =~ /^\d+$/)
                ? sprintf('%04X', $enum)
                : $enum;
            $bucket->{enumerationType} = $bucket->{enumType};
        }

        $bucket->{parentUID} = $parent_uid if defined($parent_uid);
        $changed++;

        my $feature = ref($m) eq 'HASH' ? ($m->{FeatureByUID}{$uid} // '') : '';
        my $xmlmeta = ref($m) eq 'HASH' && ref($m->{MetaByUID}{$uid}) eq 'HASH'
            ? $m->{MetaByUID}{$uid} : {};

        my @parts = (
            "uid=$uid_num", "xmlUID=$uid",
            ($feature ne '' ? "feature=$feature" : ()),
            (defined($parent_num) ? "parentUID=$parent_num" : ()),
            (defined($parent_uid) ? "parentXmlUID=$parent_uid" : ()),
            (exists($item->{access}) ? "access=$item->{access}" : ()),
            (exists($xmlmeta->{access}) ? "XMLaccess=$xmlmeta->{access}" : ()),
            (exists($item->{available}) ? "available=$item->{available}" : ()),
            (exists($xmlmeta->{available}) ? "XMLavailable=$xmlmeta->{available}" : ()),
            (exists($item->{execution}) ? "execution=$item->{execution}" : ()),
            (exists($item->{enumType}) ? "enumType=$item->{enumType}" : ()),
            (exists($item->{min}) ? "min=$item->{min}" : ()),
            (exists($item->{max}) ? "max=$item->{max}" : ()),
            (exists($item->{stepSize}) ? "stepSize=$item->{stepSize}" : ()),
            (exists($item->{default}) ? "default=" . (ref($item->{default}) ? encode_json($item->{default}) : $item->{default}) : ())
        );
        Log3 $hash->{NAME}, 5,
            "HomeConnectLocal ($hash->{NAME}) - DESCRIPTION CHANGE: " . join(' ', @parts);
    }

    # Easy-to-spot diagnostics in 'list'. Count UIDs, not parent buckets.
    $hash->{RuntimeMetaCount} = scalar(keys %{ $hash->{RuntimeMeta} });
    $hash->{RuntimeMetaLastItems} = $changed;
    # v25: monotonically increasing generation for the popup.  The browser can
    # wait for the exact /ro/allDescriptionChanges response caused by a context
    # change instead of guessing with a fixed timeout.
    $hash->{RuntimeMetaRevision} = 0 + ($hash->{RuntimeMetaRevision} // 0) + 1 if $changed;

    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - RuntimeMeta aktualisiert: "
        . "$changed Eintraege, $hash->{RuntimeMetaCount} UIDs";

    # v18: Every effective runtime-description change can alter more than the
    # literal SetList (for example ProgramMode Washing -> Drying changes the
    # currently valid program context).  FHEMWEB does not rebuild all dynamic
    # controls from longpoll alone, therefore refresh subscribed pages after
    # any real description change.  SetList is still recalculated first so
    # the reloaded page immediately receives the current command menu.
    HomeConnectLocal_RefreshFhemWebSetListIfChanged($hash, 1) if $changed;

    return $changed;
}

sub HomeConnectLocal_GetEffectiveMeta {
    my ($hash, $uid, $parent_uid) = @_;
    return {} if !$hash || !defined($uid);

    $uid = HomeConnectLocal_NormalizeHex($uid);
    $parent_uid = HomeConnectLocal_NormalizeHex($parent_uid)
        if defined($parent_uid) && $parent_uid ne '';

    my %meta;
    if (ref($hash->{Mapping}) eq 'HASH'
        && ref($hash->{Mapping}{MetaByUID}{$uid}) eq 'HASH') {
        %meta = %{ $hash->{Mapping}{MetaByUID}{$uid} };
    }

    my $rt = $hash->{RuntimeMeta}{$uid};
    if (ref($rt) eq 'HASH') {
        if (ref($rt->{global}) eq 'HASH') {
            @meta{keys %{ $rt->{global} }} = values %{ $rt->{global} };
        }

        # If a parent is known, use exactly that context.  If the caller has
        # no parent but the appliance reported exactly one runtime context,
        # that context is unambiguous and may safely overlay the XML data.
        my $ctx;
        if (defined($parent_uid)
            && ref($rt->{parents}{$parent_uid}) eq 'HASH') {
            $ctx = $rt->{parents}{$parent_uid};
        } elsif (!defined($parent_uid) && ref($rt->{parents}) eq 'HASH') {
            my @parents = keys %{ $rt->{parents} };
            $ctx = $rt->{parents}{$parents[0]} if @parents == 1;
        }
        if (ref($ctx) eq 'HASH') {
            @meta{keys %$ctx} = values %$ctx;
        }
    }

    return \%meta;
}

##############################################
# SET filter helpers
##############################################

sub HomeConnectLocal_SetExcluded {
    my ($hash, $setname, $value) = @_;
    return 0 if !$hash || !defined($setname) || $setname eq '';

    my $list = defined($value) ? $value
        : AttrVal($hash->{NAME}, 'excludeSets', '');
    return 0 if !defined($list) || $list eq '';

    for my $pattern (grep { length($_) } split(/[\s,;]+/, $list)) {
        my $regex = quotemeta($pattern);
        $regex =~ s/\\\*/.*/g;
        $regex =~ s/\\\?/./g;
        return 1 if $setname =~ /^$regex$/;
    }
    return 0;
}

##############################################
# Dynamic Set Map (from XML)
##############################################

sub HomeConnectLocal_SetSafeName {
    my ($name) = @_;
    return "" if !defined($name);
    $name =~ s/^.*\.(?:Command|Setting|Option|Program|Root)\.//;
    $name =~ s/[^A-Za-z0-9_.-]/_/g;
    return $name;
}

sub HomeConnectLocal_BuildSetMap {
    my ($hash) = @_;

    delete $hash->{HC_SETMAP};
    return if !$hash->{MappingLoaded} || ref($hash->{Mapping}) ne 'HASH';

    my $m = $hash->{Mapping};
    my %setmap;
    my %used;
    my %option_by_uid;
    my %option_by_name;
    my @programs;

    # Every UID referenced by a program is a program-option candidate.  This
    # is important for appliances whose static XML marks options unavailable
    # and only enables them through /ro/allDescriptionChanges at runtime.
    my %program_option_uid;
    for my $puid (keys %{ $m->{ProgramOptions} || {} }) {
        my $po = $m->{ProgramOptions}{$puid};
        next if ref($po) ne 'ARRAY';
        $program_option_uid{ HomeConnectLocal_NormalizeHex($_) } = 1 for @$po;
    }

    for my $uid (sort keys %{ $m->{MetaByUID} || {} }) {
        my $static = $m->{MetaByUID}{$uid};
        next if ref($static) ne 'HASH';

        my $meta = HomeConnectLocal_GetEffectiveMeta($hash, $uid);
        $meta = $static if ref($meta) ne 'HASH';

        my $kind = $static->{kind} || $meta->{kind} || '';
        my $access = $meta->{access} // $static->{access} // '';
        my $feature = $m->{FeatureByUID}{$uid};
        next if !defined($feature) || $feature eq '';

        if ($kind eq 'program') {
            # Runtime execution=SELECTANDSTART is authoritative evidence that
            # the program is usable even when static XML says available=false.
            my $execution = uc($meta->{execution} // '');
            my $available = $meta->{available};
            my $runtime_usable = ($execution =~ /(?:SELECT|START)/) ? 1 : 0;
            next if !$runtime_usable
                && defined($available) && lc("$available") eq 'false';

            my $pn = $feature;
            $pn =~ s/^.*\.Program\.//;
            # Home Connect washer/dryer mappings often repeat hierarchy names
            # (Cotton.Cotton.Cotton).  The leaf is the user-facing program.
            # Favorite programs are different: Favorite.001 is the canonical
            # program key and must not be shortened to just 001.  Keeping the
            # complete key also makes the DE/EN translation and popup lookup
            # unambiguous.
            if ($pn !~ /^Favorite\.[^.]+$/i) {
                $pn = (split(/\./, $pn))[-1] if $pn =~ /\./;
            }
            $pn =~ s/[^A-Za-z0-9_.-]/_/g;
            $pn = 'Program_' . $uid if $pn eq '';

            my $base = $pn;
            my $i = 2;
            my %existing = map { $_->{name} => 1 } @programs;
            $pn = $base . '_' . $i++ while $existing{$pn};

            my $po = $m->{ProgramOptions}{$uid};
            push @programs, {
                name => $pn,
                uid => $uid,
                feature => $feature,
                optionUIDs => (ref($po) eq 'ARRAY' ? [ @$po ] : []),
                optionMeta => (ref($m->{ProgramOptionMeta}{$uid}) eq 'HASH'
                    ? { %{ $m->{ProgramOptionMeta}{$uid} } } : {}),
                effectiveMeta => { %$meta },
            };
            next;
        }

        # ActiveProgram / SelectedProgram are protocol roots, not ordinary
        # writable settings.  Keep them in HC_SETMAP when the static XML
        # declares them, even if /ro/allDescriptionChanges temporarily reports
        # READ/NONE.  The dedicated program/start handlers decide what may be
        # sent.  This is essential for WasherDryer, where SelectedProgram is
        # reported READ at runtime although selection is performed through
        # POST /ro/selectedProgram.
        my $is_program_root = ($kind eq 'activeProgram' || $kind eq 'selectedProgram');

        # For normal settings/commands the effective runtime metadata decides
        # writability. Program options are also discovered through the XML
        # ProgramOptions relationships, even if their static access is NONE.
        my $writable = (lc($access) eq 'readwrite' || lc($access) eq 'writeonly');

        # ProgramOptions in the DeviceDescription are themselves program-context
        # capability declarations.  Some WasherDryer options are globally marked
        # access=none and only become writable inside a program.  If RuntimeMeta
        # does not explicitly provide an access value for the option context,
        # keep such an option writable based on the ProgramOptions relationship.
        my $runtime_access_explicit = 0;
        my $runtime_has_writable = 0;
        if ($program_option_uid{$uid}
            && ref($hash->{RuntimeMeta}{$uid}) eq 'HASH'
            && ref($hash->{RuntimeMeta}{$uid}{parents}) eq 'HASH') {
            for my $rp (values %{ $hash->{RuntimeMeta}{$uid}{parents} }) {
                next if ref($rp) ne 'HASH' || !exists($rp->{access});
                $runtime_access_explicit = 1;
                my $ra = lc($rp->{access} // '');
                $runtime_has_writable = 1
                    if $ra eq 'readwrite' || $ra eq 'writeonly';
            }
        }
        # A program option may be reported in several runtime parent contexts
        # (read-only status list plus writable option list).  Do not let one
        # READ context hide a simultaneously writable context.
        if ($program_option_uid{$uid}) {
            # A UID reaches this set only when it is referenced by at least one
            # writable <option refUID=...> in a concrete program.  Runtime
            # description changes may expose the same UID in READ/NONE status
            # contexts as well; those contexts must not remove the option from
            # HC_OPTION_BY_UID.  The selected-program SetList below decides
            # whether it is currently shown.
            $writable = 1;
        }
        next if !$is_program_root && !$writable;

        my $available = $meta->{available};

        # WasherDryer DryingTarget (6B06) is a program-context option.  On the
        # WNC244070 it is present as readWrite in the program definition, but
        # /ro/allDescriptionChanges may leave the option without an explicit
        # writable/available update after ProgramMode=WashingAndDrying.  Keep
        # it in the effective option map when the selected-program XML says it
        # belongs to a program; the appliance remains authoritative and will
        # accept/reject the actual /ro/values write.
        my $is_drying_target = $program_option_uid{$uid}
            && (uc($uid) eq '6B06' || $feature =~ /\.Option\.DryingTarget$/);

        # Program-option membership is program-context capability.  Do not
        # discard such UIDs here merely because a global/runtime context says
        # available=false; otherwise valid selected-program options such as
        # SpinSpeed (6002) and ProgramMode (6B03) disappear from HC_OPTION_BY_UID.
        # The selected-program SetList/runtime context decides visibility.
        next if !$is_program_root && !$program_option_uid{$uid}
            && !$is_drying_target
            && defined($available) && lc("$available") eq 'false';
        next if $kind !~ /^(?:setting|option|command|activeProgram|selectedProgram)$/;

        # A UID referenced by ProgramOptions is treated as an option even when
        # the XML kind is overly generic on a particular appliance revision.
        $kind = 'option' if $program_option_uid{$uid} && $kind eq 'option';

        my $sn = HomeConnectLocal_SetSafeName($feature);
        $sn = $kind . '_' . $uid if $sn eq '';
        $sn =~ s/_\Q$uid\E$//i if $kind eq 'option';
        $sn .= '_' . $uid if $kind ne 'option' && $used{$sn}++;

        my %e = (%$static, %$meta,
            uid => $uid,
            kind => $kind,
            feature => $feature,
            setName => $sn,
        );

        my $enum_type = $e{enumType} // $e{enumerationType};
        if (defined($enum_type)) {
            my $enid = HomeConnectLocal_NormalizeHex($enum_type);
            my $vals = $m->{EnumValues}{$enid};
            if (ref($vals) eq 'HASH') {
                my @v = map { $vals->{$_} } sort {
                    ($a =~ /^-?\d+(?:\.\d+)?$/ && $b =~ /^-?\d+(?:\.\d+)?$/) ? $a <=> $b : $a cmp $b
                } keys %$vals;
                @v = grep { defined($_) && $_ ne '' && $_ !~ /[,\s]/ } @v;
                $e{choices} = \@v if @v;
            }
        }
        if ($kind eq 'option') {
            $option_by_uid{$uid} = \%e;
            $option_by_name{$sn} = \%e;
        } else {
            $setmap{$sn} = \%e;
        }
    }

    my @program_names = map { $_->{name} } @programs;
    for my $sn (keys %setmap) {
        if ($setmap{$sn}{kind} =~ /^(?:activeProgram|selectedProgram)$/) {
            $setmap{$sn}{choices} = [ @program_names ] if @program_names;
            $setmap{$sn}{programs} = [ @programs ];
        }
    }

    $hash->{HC_SETMAP} = \%setmap;
    $hash->{HC_OPTION_BY_UID} = \%option_by_uid;
    $hash->{HC_OPTION_BY_NAME} = \%option_by_name;
    $hash->{HC_PROGRAMS} = \@programs;
    $hash->{RuntimeEffectivePrograms} = scalar(@programs);
    $hash->{RuntimeEffectiveOptions} = scalar(keys %option_by_uid);

    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - dynamische SetMap: "
        . scalar(keys %setmap) . " Sets, " . scalar(@programs)
        . " Programme, " . scalar(keys %option_by_uid) . " Optionen";
}

sub HomeConnectLocal_FindSetEntryByUID {
    my ($hash, $uid) = @_;
    $uid = HomeConnectLocal_NormalizeHex($uid);

    my $om = $hash->{HC_OPTION_BY_UID};
    return $om->{$uid}
        if ref($om) eq 'HASH' && ref($om->{$uid}) eq 'HASH';

    my $sm = $hash->{HC_SETMAP};
    if (ref($sm) eq 'HASH') {
        for my $sn (keys %$sm) {
            my $e = $sm->{$sn};
            next if ref($e) ne 'HASH';
            return $e if defined($e->{uid})
                && HomeConnectLocal_NormalizeHex($e->{uid}) eq $uid;
        }
    }

    # v14: ProgramOptions is the authoritative capability list.  Do not lose
    # an option merely because the effective map was rebuilt while a runtime
    # context temporarily advertised access=READ/NONE or available=false.
    # Reconstruct the option from the static XML mapping; the selected-program
    # and runtime overlays are applied later by ProgramOptionContextMeta().
    my $m = $hash->{Mapping};
    if (ref($m) eq 'HASH' && ref($m->{MetaByUID}{$uid}) eq 'HASH') {
        my %e = %{ $m->{MetaByUID}{$uid} };
        my $feature = $m->{FeatureByUID}{$uid} // '';
        my $sn = HomeConnectLocal_SetSafeName($feature);
        $sn = 'option_' . $uid if $sn eq '';
        $sn =~ s/_\Q$uid\E$//i;
        $e{uid} = $uid;
        $e{kind} = 'option';
        $e{feature} = $feature;
        $e{setName} = $sn;
        return \%e;
    }
    return undef;
}

sub HomeConnectLocal_CurrentSelectedProgram {
    my ($hash) = @_;
    my $n = $hash->{NAME};

    # A program selected via FHEM is stored immediately as candidate.
    # Prefer it over SelectedProgram because the appliance confirmation
    # can arrive a little later. Incoming SelectedProgram notifications
    # synchronize the candidate again in HomeConnectLocal_UpdateMappedValue().
    my $selected_name = ReadingsVal($n, "selectedProgramCandidate", "");
    $selected_name = ReadingsVal($n, "SelectedProgram", "")
        if $selected_name eq "";

    return HomeConnectLocal_FindProgram($hash, $selected_name);
}

sub HomeConnectLocal_IsBooleanProgramOption {
    my ($e) = @_;
    return 0 if ref($e) ne 'HASH' || ($e->{kind} || '') ne 'option';

    return 1 if defined($e->{default}) && $e->{default} =~ /^(?:true|false)$/i;

    # Boolean Home Connect options commonly have no enumeration and use the
    # generic boolean CID/DID pair.
    return 1 if !defined($e->{enumerationType})
             && defined($e->{refCID}) && uc($e->{refCID}) eq '01'
             && defined($e->{refDID}) && uc($e->{refDID}) eq '00';

    return 0;
}

sub HomeConnectLocal_IsProgramRunning {
    my ($hash) = @_;
    return 0 if !$hash;

    # v11: OperationState is authoritative whenever it is available.
    # ActiveProgram can remain set after the appliance has already changed
    # from Run to Finished, so using ActiveProgram first keeps FHEMWEB stuck
    # in the reduced running SET list.  ProgramMode is deliberately NOT used
    # here because Washing/Drying may be selected before a program is started.
    my $op = ReadingsVal($hash->{NAME}, 'OperationState', '');
    if (defined($op) && $op ne '') {
        return 1 if $op =~ /^(?:Run|Läuft|Pause|Paused)$/i;
        return 0 if $op =~ /^(?:Finished|Fertig|Ready|Bereit|Inactive|Ruhezustand|Aborting|Abbruch|Error)$/i;
        # For any other explicit OperationState prefer the safe non-running
        # interpretation instead of a possibly stale ActiveProgram reading.
        return 0;
    }

    # Fallback only for appliances/firmware which do not expose
    # OperationState as a reading.
    for my $rn (qw(ActiveProgram activeProgram)) {
        my $v = ReadingsVal($hash->{NAME}, $rn, '');
        next if !defined($v) || $v eq '';
        return 0 if $v =~ /^(?:0|none|inactive|ready)$/i;
        return 1;
    }

    return 0;
}

sub HomeConnectLocal_ProgramOptionContextMeta {
    my ($hash, $p, $uid, $base) = @_;
    my %ctx = ref($base) eq 'HASH' ? %$base : ();
    my $nu = HomeConnectLocal_NormalizeHex($uid);
    my $puid = ref($p) eq 'HASH' && defined($p->{uid})
        ? HomeConnectLocal_NormalizeHex($p->{uid}) : undef;

    # First apply the metadata from the option reference of the selected
    # program.  This is the static program-specific capability declaration.
    if (ref($p) eq 'HASH' && ref($p->{optionMeta}{$nu}) eq 'HASH') {
        @ctx{keys %{ $p->{optionMeta}{$nu} }} = values %{ $p->{optionMeta}{$nu} };
    }

    # Runtime metadata is context sensitive.  Do NOT use the old
    # GetEffectiveMeta($uid) shortcut here: when several parent contexts are
    # present it can select/merge an unrelated status context and make valid
    # program options disappear.  Apply global runtime data first and then the
    # exact selected-program parent, when the appliance supplied one.
    my $rt = $hash->{RuntimeMeta}{$nu};
    if (ref($rt) eq 'HASH') {
        if (ref($rt->{global}) eq 'HASH') {
            for my $k (qw(access available enumerationType enumType min max stepSize default)) {
                $ctx{$k} = $rt->{global}{$k} if exists($rt->{global}{$k});
            }
        }

        # v14: first overlay the writable live option context.  The appliance
        # uses parent 161D for the currently editable program options and puts
        # the actual enumType there (e.g. 6002->8029, 6B03->8B07).  Do not
        # assume the literal parent forever: prefer 161D when present, else any
        # writable runtime parent that is not the selected program itself.
        my $live;
        if (ref($rt->{parents}{'161D'}) eq 'HASH') {
            $live = $rt->{parents}{'161D'};
        } elsif (ref($rt->{parents}) eq 'HASH') {
            for my $rk (keys %{ $rt->{parents} }) {
                next if defined($puid) && $rk eq $puid;
                my $rp = $rt->{parents}{$rk};
                next if ref($rp) ne 'HASH';
                my $ra = lc($rp->{access} // '');
                if ($ra eq 'readwrite' || $ra eq 'writeonly') { $live = $rp; last; }
            }
        }
        if (ref($live) eq 'HASH') {
            for my $k (qw(access available enumerationType enumType min max stepSize default)) {
                $ctx{$k} = $live->{$k} if exists($live->{$k});
            }
            $ctx{runtimeLiveContext} = 1;
        }

        if (defined($puid) && ref($rt->{parents}{$puid}) eq 'HASH') {
            my $pr = $rt->{parents}{$puid};
            # The selected-program parent is a constraint context.  On the
            # WNC244070 it reports e.g. SpinSpeed min=100 and ProgramMode
            # access=READ, while the live option container 161D simultaneously
            # reports those UIDs READWRITE.  Therefore selected-program READ
            # must not downgrade a live writable option; use it for value
            # constraints and only let explicit writable access upgrade.
            for my $k (qw(enumerationType enumType min max stepSize default)) {
                $ctx{$k} = $pr->{$k} if exists($pr->{$k});
            }
            if (exists($pr->{access}) && lc($pr->{access} // '') =~ /^(?:readwrite|writeonly)$/) {
                $ctx{access} = $pr->{access};
            }
            if (exists($pr->{available}) && lc($pr->{available} // '') eq 'true') {
                $ctx{available} = $pr->{available};
            }
            $ctx{runtimeProgramContext} = 1;
        }
    }

    return \%ctx;
}

sub HomeConnectLocal_EnumMenuPairs {
    my ($hash, $e) = @_;
    return () if !$hash || ref($e) ne 'HASH';

    my $enum_type = $e->{enumType} // $e->{enumerationType};
    return () if !defined($enum_type) || $enum_type eq '';
    $enum_type = HomeConnectLocal_NormalizeHex($enum_type);
    my $ev = $hash->{Mapping}{EnumValues}{$enum_type};
    return () if ref($ev) ne 'HASH';

    my @nums = sort { $a <=> $b } grep { /^-?\d+$/ } keys %$ev;

    # v15: min/max on an enum are constraints on the numeric enum IDs, not a
    # slider.  They can wrap around the enum domain.  Temperature is the
    # important example: min=254,max=8 means Auto(254) plus Cold(0)..GC90(8).
    # SpinSpeed for Cotton can be min=100,max=140 and therefore exposes only
    # RPM1000/RPM1200/RPM1400 from the current runtime enum.
    if (defined($e->{min}) && "$e->{min}" =~ /^-?\d+(?:\.\d+)?$/
        && defined($e->{max}) && "$e->{max}" =~ /^-?\d+(?:\.\d+)?$/) {
        my ($min, $max) = (0 + $e->{min}, 0 + $e->{max});
        if ($min <= $max) {
            @nums = grep { $_ >= $min && $_ <= $max } @nums;
        } else {
            @nums = grep { $_ >= $min || $_ <= $max } @nums;
        }
    } elsif (defined($e->{min}) && "$e->{min}" =~ /^-?\d+(?:\.\d+)?$/) {
        my $min = 0 + $e->{min};
        @nums = grep { $_ >= $min } @nums;
    } elsif (defined($e->{max}) && "$e->{max}" =~ /^-?\d+(?:\.\d+)?$/) {
        my $max = 0 + $e->{max};
        @nums = grep { $_ <= $max } @nums;
    }

    return map { [ 0 + $_, $ev->{$_} ] }
           grep { defined($ev->{$_}) && $ev->{$_} ne '' && $ev->{$_} !~ /[,\s]/ }
           @nums;
}

sub HomeConnectLocal_EnumMenuValues {
    my ($hash, $e) = @_;
    return map { $_->[1] } HomeConnectLocal_EnumMenuPairs($hash, $e);
}

# ProgramMode is special on WasherDryer: the live runtime description uses
# subset enums (8B07 = Washing/WashingAndDrying, 8B06 = Washing/Drying), while
# the XML capability enum 6D01 contains the complete mode set.  A physical
# change to Drying is accepted by the appliance and reported as value 2.  For
# the SET menu use the union of the current runtime subset and the XML enum so
# all appliance-declared ProgramMode transitions can be attempted remotely;
# the appliance remains authoritative and can reject an invalid transition.
sub HomeConnectLocal_ProgramModeMenuPairs {
    my ($hash, $e) = @_;
    my @pairs = HomeConnectLocal_EnumMenuPairs($hash, $e);
    return @pairs if !$hash || ref($e) ne 'HASH' || ($e->{setName} // '') ne 'ProgramMode';

    my %seen = map { $_->[0] => 1 } @pairs;
    my $static_type = $hash->{Mapping}{EnumTypeByUID}{ HomeConnectLocal_NormalizeHex($e->{uid}) };
    if (defined($static_type) && $static_type ne '') {
        $static_type = HomeConnectLocal_NormalizeHex($static_type);
        my $sev = $hash->{Mapping}{EnumValues}{$static_type};
        if (ref($sev) eq 'HASH') {
            for my $n (sort { $a <=> $b } grep { /^-?\d+$/ } keys %$sev) {
                next if $seen{0 + $n}++;
                my $name = $sev->{$n};
                next if !defined($name) || $name eq '' || $name =~ /[,\s]/;
                push @pairs, [ 0 + $n, $name ];
            }
        }
    }
    return sort { $a->[0] <=> $b->[0] } @pairs;
}

sub HomeConnectLocal_SetList {
    my ($hash) = @_;

    my @list = ('connect:noArg', 'disconnect:noArg', 'reloadMapping:noArg');
    my $running = HomeConnectLocal_IsProgramRunning($hash);

    my $programs = $hash->{HC_PROGRAMS};
    if (ref($programs) eq 'ARRAY' && @$programs) {
        my @names = map { $_->{name} }
                    grep { ref($_) eq 'HASH' && defined($_->{name}) && $_->{name} ne '' }
                    @$programs;
        my @display_names = map { HomeConnectLocal_SetDisplayToken($hash, 'program', $_) } @names;
        push @list, 'program:' . join(',', @display_names) if @display_names && !$running;

        # Keep the first set level compact: one option selector containing
        # only options valid for the currently selected program.
        my $p = HomeConnectLocal_CurrentSelectedProgram($hash);
        if (defined($p) && ref($p->{optionUIDs}) eq 'ARRAY') {
            my @option_names;
            for my $ouid (@{ $p->{optionUIDs} }) {
                my $e = HomeConnectLocal_FindSetEntryByUID($hash, $ouid);
                next if !HomeConnectLocal_IsBooleanProgramOption($e);
                push @option_names, HomeConnectLocal_SetDisplayToken($hash, 'option', $e->{setName});
            }
            push @list, 'option:' . join(',', @option_names) if @option_names;

            # v5: expose every writable option of the selected program as a
            # normal FHEM SET.  This includes enums such as Temperature,
            # SpinSpeed, ProgramMode and DryingTarget, not only booleans.
            my %seen_option;
            for my $ouid (@{ $p->{optionUIDs} }) {
                my $e = HomeConnectLocal_FindSetEntryByUID($hash, $ouid);
                next if ref($e) ne 'HASH' || ($e->{kind} // '') ne 'option';

                # Build the menu from the current program context.  The XML
                # program reference contributes access/availability while the
                # latest runtime description contributes enumType/min/max.
                my $nu = HomeConnectLocal_NormalizeHex($ouid);
                $e = HomeConnectLocal_ProgramOptionContextMeta($hash, $p, $nu, $e);

                # v16: when the appliance supplies a live runtime context
                # (normally parent 161D), its access flag is authoritative even
                # while the appliance is idle.  A static program declaration of
                # readWrite must not make a currently READ-only option settable.
                # Example: Eco4060 Temperature is declared as an option in XML,
                # but runtime reports access=READ and fixes it to Auto.
                if ($e->{runtimeLiveContext}) {
                    my $acc = lc($e->{access} // '');
                    next if $acc !~ /^(?:readwrite|writeonly)$/;
                    next if defined($e->{available}) && lc("$e->{available}") eq 'false';
                }
                # During a running cycle be conservative even if no dedicated
                # live-context marker was produced: only explicitly writable
                # and available options belong in FHEMWEB's SetList.
                elsif ($running) {
                    my $acc = lc($e->{access} // '');
                    next if $acc !~ /^(?:readwrite|writeonly)$/;
                    next if defined($e->{available}) && lc("$e->{available}") eq 'false';
                }
                my $sn = $e->{setName} // '';
                next if $sn eq '' || $seen_option{$sn}++;
                my $dsn = HomeConnectLocal_SetDisplayToken($hash, 'option', $sn);

                my $enum_type = $e->{enumType} // $e->{enumerationType};
                if (defined($enum_type) && $enum_type ne '') {
                    $enum_type = HomeConnectLocal_NormalizeHex($enum_type);
                    my @values = (($e->{setName} // '') eq 'ProgramMode')
                        ? map { $_->[1] } HomeConnectLocal_ProgramModeMenuPairs($hash, $e)
                        : HomeConnectLocal_EnumMenuValues($hash, $e);
                    if (@values) {
                        my @dvalues = map { HomeConnectLocal_SetDisplayToken($hash, 'value', $_) } @values;
                        push @list, $dsn . ':' . join(',', @dvalues);
                        next;
                    }
                }
                if (HomeConnectLocal_IsBooleanProgramOption($e)) {
                    push @list, $dsn . ':' . join(',', map { HomeConnectLocal_SetDisplayToken($hash, 'value', $_) } qw(on off));
                    next;
                }
                if (defined($e->{min}) && defined($e->{max})) {
                    my $spec = 'slider,' . $e->{min} . ','
                        . (defined($e->{stepSize}) ? $e->{stepSize} : 1)
                        . ',' . $e->{max};
                    push @list, $dsn . ':' . $spec;
                }
            }
        }

        push @list, 'start:noArg' if !$running;
        push @list, 'stop:noArg';
        push @list, 'power:on,off' if !$running;

        # Writable XML settings become direct FHEM SET commands.
        # This gives FHEMWEB a normal two-level command/value dropdown.
        if (!$running && ref($hash->{HC_SETMAP}) eq 'HASH') {
            for my $setting_name (sort keys %{ $hash->{HC_SETMAP} }) {
                my $e = $hash->{HC_SETMAP}{$setting_name};
                next if ref($e) ne 'HASH';
                my $dsetting = HomeConnectLocal_SetDisplayToken($hash, 'option', $setting_name);
                next if ($e->{kind} // '') ne 'setting';
                next if lc($e->{access} // '') !~ /^(?:readwrite|writeonly)$/;
                next if defined($e->{available}) && lc("$e->{available}") eq 'false';
                next if $setting_name eq 'PowerState'; # handled by power:on,off

                my $enum_type = $e->{enumerationType};
                if ((!defined($enum_type) || $enum_type eq '')
                    && ref($hash->{Mapping}{EnumTypeByUID}) eq 'HASH') {
                    $enum_type = $hash->{Mapping}{EnumTypeByUID}{$e->{uid}};
                }

                if (defined($enum_type) && $enum_type ne ''
                    && ref($hash->{Mapping}{EnumValues}) eq 'HASH'
                    && ref($hash->{Mapping}{EnumValues}{$enum_type}) eq 'HASH') {
                    my $ev = $hash->{Mapping}{EnumValues}{$enum_type};
                    my @values = map { $ev->{$_} }
                        sort { $a <=> $b } grep { /^\d+$/ } keys %$ev;
                    my @dvalues = map { HomeConnectLocal_SetDisplayToken($hash, 'value', $_) } @values;
                    push @list, $dsetting . ':' . join(',', @dvalues)
                        if @dvalues;
                    next;
                }

                if (($e->{refCID} // '') eq '01'
                    && ($e->{refDID} // '') eq '00') {
                    push @list, $dsetting . ':' . join(',', map { HomeConnectLocal_SetDisplayToken($hash, 'value', $_) } qw(on off));
                    next;
                }

                if (defined($e->{min}) && defined($e->{max})) {
                    my $spec = 'slider,' . $e->{min} . ','
                        . (defined($e->{stepSize}) ? $e->{stepSize} : 1)
                        . ',' . $e->{max};
                    push @list, $dsetting . ':' . $spec;
                    next;
                }
            }
        }

        push @list, 'pause:noArg' if $running;
        push @list, 'resume:noArg' if $running;
    }

    # excludeSets only changes the visible FHEMWEB SetList.  The command
    # handler itself remains available for manual/automation calls.
    @list = grep {
        my ($setname) = split(/:/, $_, 2);
        !HomeConnectLocal_SetExcluded($hash, $setname)
    } @list;

    my $setlist = join(' ', @list);

    # Keep the real SetList unchanged for FHEMWEB and command handling, but
    # format the diagnostic LastSetList Internal so very long dynamic lists do
    # not force the complete device detail page to scroll horizontally.
    # FHEMWEB displays Internal values containing real newlines in a <pre> block.
    # Long enum/program entries are therefore split at commas for display only.
    my @display_lines;
    my $display_line = '';
    my $display_width = 120;

    for my $entry (@list) {
        my @parts;

        if (length($entry) > $display_width && $entry =~ /,/) {
            my @values = split(/,/, $entry, -1);
            for my $i (0 .. $#values) {
                my $part = $values[$i];
                $part .= ',' if $i < $#values;
                push @parts, $part;
            }
        } else {
            @parts = ($entry);
        }

        for my $part (@parts) {
            my $separator = ($display_line ne '' && $display_line !~ /,$/) ? ' ' : '';
            if ($display_line ne ''
                && length($display_line) + length($separator) + length($part) > $display_width) {
                push @display_lines, $display_line;
                $display_line = $part;
            } else {
                $display_line .= $separator . $part;
            }
        }
    }
    push @display_lines, $display_line if $display_line ne '';

    # Use real newline characters. FHEMWEB escapes literal HTML in Internals,
    # so <br> would be shown as text instead of producing a line break.
    $hash->{LastSetList} = join("\n", @display_lines);
    $HomeConnectLocal_Private{$hash->{NAME}}{LastSetListRaw} = $setlist;

    return $setlist;
}

# v18: FHEMWEB builds dynamic controls server-side. Longpoll updates readings,
# but does not reliably rebuild the complete program/option context.  With
# $force set, reload subscribed pages after every real runtime-description
# change; without it retain the v17 SetList-change behaviour.
sub HomeConnectLocal_RefreshFhemWebSetListIfChanged {
    my ($hash, $force) = @_;
    return if !$hash;

    # v20: while the configuration popup is applying a sequence of program
    # options, keep FHEMWEB on the current page. The popup explicitly ends the
    # session afterwards and requests one final refresh.
    if ($hash->{HC_CONFIG_SESSION}) {
        $hash->{HC_CONFIG_REFRESH_PENDING} = 1 if $force;
        return;
    }

    my $old = $HomeConnectLocal_Private{$hash->{NAME}}{LastSetListRaw};
    my $new = HomeConnectLocal_SetList($hash);

    # On the first calculation there is no browser-side list to invalidate.
    return if !defined($old) && !$force;
    return if !$force && $old eq $new;

    my $why = (defined($old) && $old ne $new)
        ? 'SetList geaendert'
        : 'Runtime-Kontext geaendert';
    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - FHEMWEB $why -> Browser-Refresh";
    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - FHEMWEB SetList ALT: " . (defined($old) ? $old : '<undef>');
    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - FHEMWEB SetList NEU: $new";

    no strict 'vars';
    return if !defined(&FW_directNotify);

    for my $web (keys %defs) {
        next if ref($defs{$web}) ne 'HASH';
        next if ($defs{$web}{TYPE} // '') ne 'FHEMWEB';

        # FILTER=<device> limits the notification to FHEMWEB longpoll clients
        # which currently show/subscribe to this HomeConnectLocal device.
        eval {
            FW_directNotify(
                'FILTER=' . $hash->{NAME},
                '#FHEMWEB:' . $web,
                "location.reload(true)",
                ''
            );
        };
        Log3 $hash->{NAME}, 5,
            "HomeConnectLocal ($hash->{NAME}) - FHEMWEB Refresh $web fehlgeschlagen: $@"
            if $@;
    }

    return;
}


sub HomeConnectLocal_FindProgram {
    my ($hash, $wanted) = @_;
    return undef if !defined($wanted) || $wanted eq '';

    my $programs = $hash->{HC_PROGRAMS};
    return undef if ref($programs) ne 'ARRAY';

    for my $p (@$programs) {
        next if ref($p) ne 'HASH';
        return $p if defined($p->{name}) && $p->{name} eq $wanted;
    }
    return undef;
}

sub HomeConnectLocal_FindProgramRoot {
    my ($hash, $kind) = @_;
    my $sm = $hash->{HC_SETMAP};
    return undef if ref($sm) ne 'HASH';

    for my $sn (keys %$sm) {
        my $e = $sm->{$sn};
        next if ref($e) ne 'HASH';
        return $e if ($e->{kind} || '') eq $kind;
    }
    return undef;
}

##############################################
# Mapping
##############################################

sub HomeConnectLocal_GetMappedFeature {
    my ($hash, $uid) = @_;

    return undef
        if !defined($uid) ||
           !$hash->{MappingLoaded};

    return
        $hash->{Mapping}{FeatureByUID}{
            HomeConnectLocal_NormalizeProtocolUID(
                $uid
            )
        };
}


sub HomeConnectLocal_GetZoneReadingName {
    my ($hash, $feature) = @_;

    return undef
        if !defined($feature) ||
           !$hash->{MappingLoaded};

    # Nur Features der Form ...Zone.<id>.<property>.
    return undef
        if $feature !~ /^(.*\.Zone\.)(\d+)\.([^.]+)$/;

    my ($prefix, $zone_id, $property) =
        ($1, $2, $3);

    # Die ZoneSelector-UID derselben Zone direkt aus dem
    # FeatureMapping bestimmen. Keine feste Zonentabelle.
    my $selector_feature =
        $prefix . $zone_id . ".ZoneSelector";

    my $selector_uid =
        $hash->{Mapping}{UIDByFeature}{$selector_feature};

    return undef
        if !defined($selector_uid);

    my $meta =
        $hash->{Mapping}{MetaByUID}{$selector_uid};

    return undef
        if ref($meta) ne 'HASH';

    my $selector_value =
        $meta->{initValue};

    # Falls kein initValue vorhanden ist, ist bei den Home-Connect-
    # Zonen die numerische ID selbst der Selector-Wert. Das ist keine
    # Zonentabelle, sondern nur der aus dem Featurepfad gelesene Wert.
    $selector_value = $zone_id
        if !defined($selector_value) ||
           $selector_value eq '';

    my $enum_type =
        $hash->{Mapping}{EnumTypeByUID}{$selector_uid};

    return undef
        if !defined($enum_type);

    my $zone_name =
        $hash->{Mapping}{EnumValues}{$enum_type}{$selector_value};

    return undef
        if !defined($zone_name) ||
           $zone_name eq '';

    my $reading =
        $zone_name . "_" . $property;

    $reading =~ s/[^A-Za-z0-9_.-]/_/g;

    return $reading;
}


sub HomeConnectLocal_GetShortReadingName {
    my ($hash, $feature, $uid) = @_;

    return undef
        if !defined($feature) ||
           $feature eq '';

    # Zonenname vollstaendig aus DeviceDescription + FeatureMapping
    # ableiten, z.B. Zone.100.PowerLevel -> FrontLeft_PowerLevel.
    my $zone_reading =
        HomeConnectLocal_GetZoneReadingName(
            $hash,
            $feature
        );

    return $zone_reading
        if defined($zone_reading) &&
           $zone_reading ne '';

    my @p = split(/\./, $feature);
    return undef if !@p;

    my $r = $p[-1];

    # Wenn eine Zone zwar erkannt, aber in der XML nicht aufgeloest
    # werden konnte, bleibt der bisherige eindeutige Fallback erhalten.
    if (
        @p >= 3 &&
        $p[-3] eq 'Zone' &&
        $p[-2] =~ /^\d+$/
    ) {
        $r = 'Zone_' . $p[-2] . '_' . $p[-1];
    }

    $r =~ s/[^A-Za-z0-9_.-]/_/g;

    return $r;
}


sub HomeConnectLocal_MapProgramValue {
    my ($hash, $value) = @_;

    return $value
        if !defined($value) ||
           ref($value);

    # 0 bedeutet bei den Program-Referenzen "kein Programm" und soll
    # nicht gegen eine Feature-UID aufgeloest werden.
    return $value
        if $value !~ /^\d+$/ ||
           $value == 0;

    my $pu =
        HomeConnectLocal_NormalizeProtocolUID($value);

    # Prefer the canonical short name already generated for HC_PROGRAMS.
    # WasherDryer feature names contain several hierarchy components, e.g.
    #   ...Program.Cotton.Cotton.Cotton
    # while the FHEM program name is simply "Cotton".  Returning the full
    # suffix here used to overwrite selectedProgramCandidate and made the
    # subsequent option SET fail with "Kein Programm ausgewaehlt".
    if (ref($hash->{HC_PROGRAMS}) eq 'ARRAY') {
        for my $p (@{ $hash->{HC_PROGRAMS} }) {
            next if ref($p) ne 'HASH' || !defined($p->{uid});
            return $p->{name}
                if HomeConnectLocal_NormalizeHex($p->{uid}) eq $pu
                && defined($p->{name}) && $p->{name} ne '';
        }
    }

    my $pf =
        $hash->{Mapping}{FeatureByUID}{$pu};

    return $value
        if !defined($pf);

    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - "
        . "PROGRAM MAP: $value -> $pu -> $pf";

    return $1
        if $pf =~ /\.Program\..*\.([^\.]+)$/;

    return $1
        if $pf =~ /\.Program\.([^\.]+)$/;

    return $pf;
}


sub HomeConnectLocal_MapValue {
    my ($hash, $uid, $value) = @_;

    return $value
        if !defined($value);

    return encode_json($value)
        if ref($value);

    return $value
        if !$hash->{MappingLoaded};

    my $nu =
        HomeConnectLocal_NormalizeProtocolUID($uid);

    my $feature =
        $hash->{Mapping}{FeatureByUID}{$nu};

    # ActiveProgram / SelectedProgram nicht anhand fester UIDs erkennen,
    # sondern anhand des Feature-Namens aus der FeatureMapping.xml.
    # Das funktioniert damit auch fuer zonale Programme.
    if (
        defined($feature) &&
        $feature =~ /\.(?:ActiveProgram|SelectedProgram)$/
    ) {
        return HomeConnectLocal_MapProgramValue(
            $hash,
            $value
        );
    }

    my $et =
        $hash->{Mapping}{EnumTypeByUID}{$nu};

    if (
        defined($et) &&
        exists($hash->{Mapping}{EnumValues}{$et}{$value})
    ) {
        my $mapped =
            $hash->{Mapping}{EnumValues}{$et}{$value};

        # Die Art des Enums kommt aus der FeatureMapping.xml.
        # Fuer *.EnumType.PowerLevel sind die dort hinterlegten
        # numerischen Bezeichnungen 10,15,...90 die Anzeige fuer
        # 1.0,1.5,...9.0. Sonderwerte wie Off/KeepWarm/Boost bleiben Text.
        my $enum_key =
            $hash->{Mapping}{EnumKeyByENID}{$et};

        if (
            defined($enum_key) &&
            $enum_key =~ /\.EnumType\.PowerLevel$/ &&
            defined($mapped) &&
            $mapped =~ /^\d+$/ &&
            $mapped >= 10 &&
            $mapped <= 90
        ) {
            return sprintf('%.1f', $mapped / 10);
        }

        return $mapped;
    }

    return $value;
}


sub HomeConnectLocal_RefreshProgramDescription {
    my ($hash, $reason) = @_;
    return if !$hash || !$hash->{MappingLoaded};
    my $now = time();
    if (defined($hash->{LAST_PROGRAM_CONTEXT_REFRESH})
        && ($now - $hash->{LAST_PROGRAM_CONTEXT_REFRESH}) < 1.0) {
        Log3 $hash->{NAME}, 5,
            "HomeConnectLocal ($hash->{NAME}) - PROGRAM CONTEXT REFRESH skipped (debounce): "
            . ($reason // 'change');
        return;
    }
    $hash->{LAST_PROGRAM_CONTEXT_REFRESH} = $now;
    my $type = lc($hash->{Mapping}{DeviceInfo}{type} // '');
    # WasherDryer and Dishwasher both change the writable programme options
    # dynamically after SelectedProgram/option changes.  The popup therefore
    # needs a fresh /ro/allDescriptionChanges context for both appliance types.
    return if $type ne 'washerdryer' && $type ne 'dishwasher';

    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - PROGRAM CONTEXT REFRESH: "
        . ($reason // 'change') . " -> GET /ro/allDescriptionChanges";

    HomeConnectLocal_SendProtocol(
        $hash,
        "/ro/allDescriptionChanges",
        1,
        "GET"
    );
}

sub HomeConnectLocal_UpdateMappedValue {
    my ($hash, $uid, $value) = @_;

    return
        if !defined($uid) ||
           !$hash->{MappingLoaded};

    my $f =
        HomeConnectLocal_GetMappedFeature(
            $hash,
            $uid
        );

    return
        if !defined($f);

    my $r =
        HomeConnectLocal_GetShortReadingName(
            $hash,
            $f,
            $uid
        );

    return
        if !defined($r) ||
           $r eq "";

    my $mv =
        HomeConnectLocal_MapValue(
            $hash,
            $uid,
            $value
        );

    HomeConnectLocal_ReadingsSingleUpdate(
        $hash,
        $r,
        $mv,
        1
    );

    # Keep the local program candidate in sync with the appliance.
    # This is important for the dynamic set option:<...> list:
    # - after "set ... program ..." the candidate is available immediately
    # - after a program change at the appliance SelectedProgram updates it
    if ($f =~ /\.SelectedProgram$/) {
        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "selectedProgramCandidate",
            $mv,
            1
        );
        HomeConnectLocal_RefreshProgramDescription($hash, "SelectedProgram=$mv");
    }

    # v19: ProgramMode, Temperature and SpinSpeed are all context-sensitive
    # WasherDryer program options.  A confirmed NOTIFY for any of them can
    # change the effective runtime description and therefore the FHEMWEB SET
    # controls.  Refresh only after the appliance has confirmed the value.
    my $nuid = HomeConnectLocal_NormalizeHex($uid);
    if ($f =~ /\.Option\.(?:ProgramMode|Temperature|SpinSpeed)$/
        || $nuid eq '6B03' || $nuid eq '6001' || $nuid eq '6002') {
        my $ctx_name = $f;
        $ctx_name =~ s/^.*\.Option\.//;
        $ctx_name = $nuid if !defined($ctx_name) || $ctx_name eq '';
        HomeConnectLocal_RefreshProgramDescription($hash, "$ctx_name=$mv");
    }

    # v11: A program ending changes which SET commands/options are valid.
    # Refresh the runtime description on OperationState transitions as well.
    # In particular Finished must immediately leave the reduced Run menu; an
    # off/on cycle must not be necessary.  The existing debounce collapses
    # adjacent context changes into a single request.
    if ($f =~ /\.OperationState$/) {
        HomeConnectLocal_RefreshProgramDescription($hash, "OperationState=$mv");
    }

    Log3 $hash->{NAME}, 5,
        "HomeConnectLocal ($hash->{NAME}) - "
        . "MAP $uid -> $f -> $r = $mv";
}


##############################################
# Random / Base64
##############################################

sub HomeConnectLocal_RandomBytes {
    my ($length) = @_;

    my $data = '';

    if (
        open(
            my $fh,
            '<',
            '/dev/urandom'
        )
    ) {

        binmode($fh);

        my $r =
            read(
                $fh,
                $data,
                $length
            );

        close($fh);

        return $data
            if defined($r) &&
               $r == $length;
    }


    $data .=
        chr(
            int(rand(256))
        )
        for 1 .. $length;

    return $data;
}


sub HomeConnectLocal_Base64UrlDecode {
    my ($v) = @_;

    return undef
        if !defined($v);

    $v =~
        s/^\s+|\s+$//g;

    $v =~
        tr/-_/+\//;

    $v .= '='
        while length($v) % 4;

    return
        decode_base64(
            $v
        );
}


##############################################
# AES
#
# Bleibt im Modul, wird für unseren aktuellen
# TLS-Test aber nicht verändert.
##############################################

sub HomeConnectLocal_AESInit {
    my ($hash, $psk, $iv) = @_;

    my $n = $hash->{NAME};

    # Remove AES fields left in the device hash by older module versions.
    # The active session state is stored only in %HomeConnectLocal_Private.
    delete @{$hash}{grep { /^AES_/ } keys %{$hash}};

    if (!defined($psk) || length($psk) != 32) {
        Log3 $n, 3,
            "HomeConnectLocal ($n) - AES: PSK muss exakt 32 Byte lang sein.";
        return;
    }

    if (!defined($iv) || length($iv) != 16) {
        Log3 $n, 3,
            "HomeConnectLocal ($n) - AES: IV muss exakt 16 Byte lang sein.";
        return;
    }

    #
    # hcpy:
    #
    # enckey = HMAC-SHA256(psk, "ENC")
    # mackey = HMAC-SHA256(psk, "MAC")
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_ENC_KEY} =
        hmac_sha256(
            "ENC",
            $psk
        );

    $HomeConnectLocal_Private{$hash->{NAME}}{AES_MAC_KEY} =
        hmac_sha256(
            "MAC",
            $psk
        );

    #
    # Der originale IV bleibt unverändert.
    #
    # Er wird für die HMAC-Berechnung bei JEDER
    # Nachricht verwendet.
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_IV} = $iv;

    #
    # CBC-Zustand.
    #
    # hcpy verwendet zwei getrennte, stateful
    # AES-CBC-Instanzen.
    #
    # Wir bilden das in Perl durch getrennte
    # aktuelle IVs nach.
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_TX_IV} = $iv;
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_IV} = $iv;

    #
    # hcpy:
    #
    # last_rx_hmac = bytes(16)
    # last_tx_hmac = bytes(16)
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_LAST_TX_HMAC} =
        "\x00" x 16;

    $HomeConnectLocal_Private{$hash->{NAME}}{AES_LAST_RX_HMAC} =
        "\x00" x 16;

    #
    # Zähler nur zur Diagnose.
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_TX_COUNT} = 0;
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_COUNT} = 0;

    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "AES Verschlüsselung initialisiert "
        . "PSK=32 Byte IV=16 Byte.";

    return 1;
}


sub HomeConnectLocal_AESMac {
    my ($hash, $direction, $last_hmac, $enc) = @_;

    #
    # Exakt entsprechend hcpy:
    #
    # hmac_msg =
    #     original_iv
    #     + direction
    #     + previous_hmac
    #     + encrypted_message
    #
    my $msg =
          $HomeConnectLocal_Private{$hash->{NAME}}{AES_IV}
        . $direction
        . $last_hmac
        . $enc;

    return substr(
        hmac_sha256(
            $msg,
            $HomeConnectLocal_Private{$hash->{NAME}}{AES_MAC_KEY}
        ),
        0,
        16
    );
}


sub HomeConnectLocal_AESEncrypt {
    my ($hash, $clear) = @_;

    my $n = $hash->{NAME};

    #
    # hcpy arbeitet mit UTF-8 Bytes.
    #
    # encode_json liefert für unsere bisherigen
    # Protokollnachrichten bereits einen Byte-String.
    #

    my $clear_len =
        length($clear);

    #
    # Exakt das Home-Connect-Padding aus hcpy.
    #
    my $pad_len =
        16 - ($clear_len % 16);

    #
    # Ein einzelnes Padding-Byte reicht nicht,
    # weil mindestens:
    #
    # 00 + padLength
    #
    # benötigt wird.
    #
    if ($pad_len == 1) {
        $pad_len += 16;
    }

    my $padding =
          "\x00"
        . HomeConnectLocal_RandomBytes(
            $pad_len - 2
        )
        . chr($pad_len);

    my $plain =
        $clear . $padding;

    #
    # Das muss block-aligned sein.
    #
    if (length($plain) % 16 != 0) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "AES TX Paddingfehler: "
            . "plainLen="
            . length($plain);

        return undef;
    }

    my $current_iv =
        $HomeConnectLocal_Private{$hash->{NAME}}{AES_TX_IV};

    #
    # WICHTIG:
    #
    # Crypt::Mode::CBC bekommt bereits gepaddete
    # Daten und darf deshalb kein zusätzliches
    # Padding hinzufügen.
    #
    my $cbc =
        Crypt::Mode::CBC->new(
            'AES',
            0
        );

    my $enc =
        $cbc->encrypt(
            $plain,
            $HomeConnectLocal_Private{$hash->{NAME}}{AES_ENC_KEY},
            $current_iv
        );

    if (!defined($enc)) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "AES TX Verschlüsselung fehlgeschlagen.";

        return undef;
    }

    #
    # Bei CBC wird für die nächste Nachricht
    # der letzte Ciphertext-Block zum IV.
    #
    my $next_iv =
        substr(
            $enc,
            -16
        );

    #
    # hcpy:
    #
    # last_tx_hmac =
    #   HMAC(
    #       originalIV
    #       + 0x45
    #       + previousTXHMAC
    #       + ciphertext
    #   )[0:16]
    #
    my $mac =
        HomeConnectLocal_AESMac(
            $hash,
            "\x45",
            $HomeConnectLocal_Private{$hash->{NAME}}{AES_LAST_TX_HMAC},
            $enc
        );
   
    #
    # Erst nach erfolgreicher Berechnung
    # Zustand fortschreiben.
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_TX_IV} =
        $next_iv;

    $HomeConnectLocal_Private{$hash->{NAME}}{AES_LAST_TX_HMAC} =
        $mac;

    $HomeConnectLocal_Private{$hash->{NAME}}{AES_TX_COUNT}++;

    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "AES TX #"
        . $HomeConnectLocal_Private{$hash->{NAME}}{AES_TX_COUNT}
        . " clear="
        . $clear_len
        . " padded="
        . length($plain)
        . " encrypted="
        . length($enc)
        . " framePayload="
        . (length($enc) + 16);

    return
        $enc . $mac;
}


sub HomeConnectLocal_AESDecrypt {
    my ($hash, $buf) = @_;

    my $n = $hash->{NAME};

    #
    # Mindestens:
    #
    # 16 Byte Ciphertext
    # 16 Byte HMAC
    #
    if (!defined($buf) || length($buf) < 32) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "AES RX Nachricht zu kurz.";

        return undef;
    }

    if (length($buf) % 16 != 0) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "AES RX Nachricht nicht "
            . "16-Byte-ausgerichtet: "
            . length($buf);

        return undef;
    }


    my $enc =
        substr(
            $buf,
            0,
            -16
        );

    my $their_hmac =
        substr(
            $buf,
            -16
        );


    #
    # ---------------------------------------------------------
    # Aktuellen RX-State sichern.
    #
    # WICHTIG:
    # Hier wird noch NICHTS verändert.
    # ---------------------------------------------------------
    #
    my $previous_hmac =
        $HomeConnectLocal_Private{$hash->{NAME}}{AES_LAST_RX_HMAC};

    my $current_iv =
        $HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_IV};


    #
    # Erwarteten HMAC berechnen.
    #
    # Referenz:
    #
    # original IV
    # + 0x43
    # + previous RX HMAC
    # + ciphertext
    #
    my $our_hmac =
        HomeConnectLocal_AESMac(
            $hash,
            "\x43",
            $previous_hmac,
            $enc
        );


    #
    # ---------------------------------------------------------
    # HMAC FEHLER
    #
    # Jetzt alle relevanten Werte ausgeben.
    # ---------------------------------------------------------
    #
    if ($their_hmac ne $our_hmac) {

        my $next_rx =
            ($HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_COUNT} // 0) + 1;

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX #$next_rx HMAC FEHLER";

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX framePayload="
            . length($buf)
            . " encrypted="
            . length($enc);

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX receivedHMAC="
            . unpack("H*", $their_hmac);

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX calculatedHMAC="
            . unpack("H*", $our_hmac);

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX previousHMAC="
            . unpack("H*", $previous_hmac);

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX currentCBCIV="
            . unpack("H*", $current_iv);

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX originalIV="
            . unpack("H*", $HomeConnectLocal_Private{$hash->{NAME}}{AES_IV});

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX ciphertextFirst16="
            . unpack(
                "H*",
                substr($enc, 0, 16)
            );

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES RX ciphertextLast16="
            . unpack(
                "H*",
                substr($enc, -16)
            );

        #
        # Ganz wichtig:
        #
        # Bei HMAC-Fehler KEINEN State verändern.
        #
        return undef;
    }


    #
    # Erst nach erfolgreicher HMAC-Prüfung
    # RX-HMAC übernehmen.
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_LAST_RX_HMAC} =
        $their_hmac;


    #
    # CBC entschlüsseln.
    #
    my $cbc =
        Crypt::Mode::CBC->new(
            'AES',
            0
        );

    my $clear =
        $cbc->decrypt(
            $enc,
            $HomeConnectLocal_Private{$hash->{NAME}}{AES_ENC_KEY},
            $current_iv
        );


    if (!defined($clear) || !length($clear)) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "AES RX Entschlüsselung fehlgeschlagen.";

        return undef;
    }


    #
    # CBC-State für nächste Nachricht.
    #
    $HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_IV} =
        substr(
            $enc,
            -16
        );


    #
    # Padding entfernen.
    #
    my $pad_len =
        ord(
            substr(
                $clear,
                -1,
                1
            )
        );


    if (
        $pad_len <= 0 ||
        $pad_len > length($clear)
    ) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "AES RX Padding ungültig: "
            . "$pad_len";

        return undef;
    }


    my $result =
        substr(
            $clear,
            0,
            length($clear) - $pad_len
        );


    $HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_COUNT}++;


    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "AES RX #"
        . $HomeConnectLocal_Private{$hash->{NAME}}{AES_RX_COUNT}
        . " encrypted="
        . length($enc)
        . " clear="
        . length($result);


    return $result;
}

##############################################
# WebSocket Upgrade
##############################################

sub HomeConnectLocal_OpenWebSocket {
    my (
        $hash,
        $socket,
        $host_header
    ) = @_;

    my $name =
        $hash->{NAME};


    my $key =
        encode_base64(
            HomeConnectLocal_RandomBytes(
                16
            ),
            ""
        );

    $key =~
        s/\s//g;


    my $crlf =
        "\r\n";


    my $req =
          "GET /homeconnect HTTP/1.1"
        . $crlf
        . "Host: "
        . $host_header
        . $crlf
        . "Upgrade: websocket"
        . $crlf
        . "Connection: Upgrade"
        . $crlf
        . "Sec-WebSocket-Key: "
        . $key
        . $crlf
        . "Sec-WebSocket-Version: 13"
        . $crlf
        . $crlf;


    my $len =
        length($req);

    my $offset =
        0;


    while ($offset < $len) {

        my $written =
            syswrite(
                $socket,
                $req,
                $len - $offset,
                $offset
            );


        if (!defined($written)) {

            Log3 $name, 3,
                "HomeConnectLocal ($name) - "
                . "WebSocket Handshake konnte "
                . "nicht gesendet werden: $!";

            return 0;
        }


        if ($written == 0) {

            Log3 $name, 3,
                "HomeConnectLocal ($name) - "
                . "WebSocket Handshake: "
                . "Socket beim Schreiben geschlossen.";

            return 0;
        }


        $offset +=
            $written;
    }


    Log3 $name, 5,
        "HomeConnectLocal ($name) - "
        . "WebSocket Handshake: "
        . "$offset/$len Bytes gesendet.";


    $hash->{WSHandshake} =
        1;


    HomeConnectLocal_ReadingsSingleUpdate(
        $hash,
        "state",
        "handshake_sent",
        1
    );


    return 1;
}


##############################################
# Connect
##############################################

sub HomeConnectLocal_Connect {
    my ($hash) = @_;

    return
        if !$hash;

    my $name =
        $hash->{NAME};

    return
        if !$name;

    return
        if AttrVal(
            $name,
            "disable",
            0
        );

    my $host =
        $hash->{Host};

    my $ct =
        uc(
            AttrVal(
                $name,
                "connectionType",
                "TLS"
            )
        );

    $hash->{ConnectionType} =
        $ct;

    my $psk =
        HomeConnectLocal_Base64UrlDecode(
            AttrVal(
                $name,
                "encryptionKey",
                ""
            )
        );

    if (
        !defined($psk) ||
        length($psk) != 32
    ) {

        Log3 $name, 3,
            "HomeConnectLocal ($name) - "
            . "encryptionKey ungültig!";

        return;
    }

    HomeConnectLocal_Undefine(
        $hash
    );

    $hash->{PARTIAL} =
        "";

    delete
        $hash->{WSHandshake};


    #
    # ==========================================
    # AES
    # ==========================================
    #
    if ($ct eq "AES") {

        my $iv =
            HomeConnectLocal_Base64UrlDecode(
                AttrVal(
                    $name,
                    "iv",
                    ""
                )
            );

        if (
            !defined($iv) ||
            length($iv) != 16
        ) {

            Log3 $name, 3,
                "HomeConnectLocal ($name) - "
                . "AES IV ungültig "
                . "(16 Byte erwartet).";

            return;
        }

        return
            if !HomeConnectLocal_AESInit(
                $hash,
                $psk,
                $iv
            );

        my $s =
            IO::Socket::INET->new(
                PeerAddr => $host,
                PeerPort => 80,
                Proto    => 'tcp',
                Timeout  => 5
            );

        if (!$s) {

            Log3 $name, 5,
                "HomeConnectLocal ($name) - "
                . "AES Verbindung zu "
                . "$host:80 fehlgeschlagen: $!";

            InternalTimer(
                time() + 10,
                "HomeConnectLocal_Connect",
                $hash,
                0
            );

            return;
        }

        Log3 $name, 2,
            "HomeConnectLocal ($name) - "
            . "TCP/AES Kanal zu "
            . "$host:80 verbunden.";

        my $ok =
            HomeConnectLocal_OpenWebSocket(
                $hash,
                $s,
                "$host:80"
            );

        if (!$ok) {

            close($s);

            delete
                $hash->{WSHandshake};

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "closed",
                1
            );

            InternalTimer(
                time() + 10,
                "HomeConnectLocal_Connect",
                $hash,
                0
            );

            return;
        }

        $s->blocking(0);

        $hash->{FD} =
            fileno($s);

        $hash->{CD} =
            $s;

        $main::selectlist{$name} =
            $hash;

        Log3 $name, 5,
            "HomeConnectLocal ($name) - "
            . "AES WebSocket Handshake gesendet.";

        return;
    }


    #
    # ==========================================
    # TLS / PSK
    # ==========================================
    #
    # FUNKTIONIERENDEN TLS-PFAD NICHT VERÄNDERN.
    #

    my $hex =
        unpack(
            "H*",
            $psk
        );

    my @ip =
        split(
            /\./,
            $host
        );

    my $lp =
        10000 +
        $ip[-1];

    $hash->{LocalPort} =
        $lp;

    Log3 $name, 5,
        "HomeConnectLocal ($name) - "
        . "Starte TLS-PSK Proxy "
        . "auf Port $lp";

    system(
        "pkill -f 'socat.*LISTEN:$lp'"
    );

    my $cmd =
          "socat "
        . "TCP-LISTEN:$lp,reuseaddr,fork "
        . "EXEC:'openssl s_client "
        . "-connect $host\\:443 "
        . "-tls1_2 "
        . "-psk $hex "
        . "-noservername "
        . "-cipher ECDHE-PSK-CHACHA20-POLY1305 "
        . "-quiet "
        . "-ign_eof',nofork &";

    system($cmd);

    InternalTimer(
        time() + 0.5,
        sub {

            my $s =
                IO::Socket::INET->new(
                    PeerAddr => '127.0.0.1',
                    PeerPort => $lp,
                    Proto    => 'tcp',
                    Blocking => 0
                );

            if (!$s) {

                Log3 $name, 3,
                    "HomeConnectLocal ($name) - "
                    . "Verbindung zum TLS-Proxy "
                    . "auf Port $lp fehlgeschlagen.";

                InternalTimer(
                    time() + 10,
                    "HomeConnectLocal_Connect",
                    $hash,
                    0
                );

                return;
            }

            $hash->{FD} =
                fileno($s);

            $hash->{CD} =
                $s;

            $main::selectlist{$name} =
                $hash;

            Log3 $name, 2,
                "HomeConnectLocal ($name) - "
                . "TCP/TLS Kanal aktiv.";

            my $ok =
                HomeConnectLocal_OpenWebSocket(
                    $hash,
                    $s,
                    $host
                );

            if ($ok) {

                Log3 $name, 5,
                    "HomeConnectLocal ($name) - "
                    . "WebSocket Handshake gesendet.";
            }

        },
        $hash
    );

    return;
}
##############################################
# WebSocket Frame
##############################################

sub HomeConnectLocal_WSFrame {
    my (
        $payload,
        $opcode
    ) = @_;

    $opcode = 0x1
        if !defined($opcode);


    my $len =
        length($payload);


    my $frame =
        pack(
            "C",
            0x80 |
            ($opcode & 0x0f)
        );


    my $mask =
        HomeConnectLocal_RandomBytes(
            4
        );


    if ($len < 126) {

        $frame .=
            pack(
                "C",
                0x80 | $len
            );

    }
    elsif ($len <= 65535) {

        $frame .=
              pack(
                  "C",
                  0x80 | 126
              )
            . pack(
                  "n",
                  $len
              );

    }
    else {

        my $hi =
            int(
                $len /
                4294967296
            );

        my $lo =
            $len %
            4294967296;


        $frame .=
              pack(
                  "C",
                  0x80 | 127
              )
            . pack(
                  "N2",
                  $hi,
                  $lo
              );
    }


    my $m =
        '';


    for (
        my $i = 0;
        $i < $len;
        $i++
    ) {

        $m .= chr(
            ord(
                substr(
                    $payload,
                    $i,
                    1
                )
            )
            ^
            ord(
                substr(
                    $mask,
                    $i % 4,
                    1
                )
            )
        );
    }


    return
          $frame
        . $mask
        . $m;
}


sub HomeConnectLocal_WSFrame_Control {
    my ($op, $p) = @_;

    $p = ''
        if !defined($p);

    return undef
        if length($p) > 125;

    return
        HomeConnectLocal_WSFrame(
            $p,
            $op
        );
}


##############################################
# Send
##############################################

sub HomeConnectLocal_SendRaw {
    my ($hash, $json) = @_;

    my $n =
        $hash->{NAME};

    my $s =
        $hash->{CD};

    return
        if !$s;


    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "SEND RAW: $json";


    my (
        $payload,
        $op
    ) =
        (
            $json,
            0x1
        );


    if (
        ($hash->{ConnectionType} // "TLS")
        eq "AES"
    ) {

        $payload =
            HomeConnectLocal_AESEncrypt(
                $hash,
                $json
            );

        return undef
            if !defined($payload);

        $op =
            0x2;
    }


    my $frame =
        HomeConnectLocal_WSFrame(
            $payload,
            $op
        );


    my $len =
        length($frame);

    my $off =
        0;


    my $was_blocking =
        $s->blocking();


    $s->blocking(1);


    while ($off < $len) {

        my $written =
            syswrite(
                $s,
                $frame,
                $len - $off,
                $off
            );


        if (!defined($written)) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "SEND fehlgeschlagen "
                . "bei $off/$len Bytes: $!";

            $s->blocking(
                $was_blocking
            );

            return undef;
        }


        if ($written == 0) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "SEND Socket geschlossen "
                . "bei $off/$len Bytes.";

            $s->blocking(
                $was_blocking
            );

            return undef;
        }


        $off +=
            $written;
    }


    $s->blocking(
        $was_blocking
    );


    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "SEND vollständig: "
        . "$off/$len Bytes";


    return 1;
}


sub HomeConnectLocal_SendJSON {
    my ($hash, $data) = @_;

    return
        HomeConnectLocal_SendRaw(
            $hash,
            encode_json(
                $data
            )
        );
}


sub HomeConnectLocal_SendProtocol {
    my (
        $hash,
        $res,
        $ver,
        $act,
        $data
    ) = @_;


    return
        if !defined(
            $hash->{SessionID}
        ) ||
           !defined(
            $hash->{TxMsgID}
        );


    my $m = {
        sID      => 0 + $hash->{SessionID},
        msgID    => 0 + $hash->{TxMsgID},
        resource => $res,
        version  => 0 + $ver,
        action   => $act
    };


    $m->{data} =
        [$data]
        if defined($data);


    my $r =
        HomeConnectLocal_SendRaw(
            $hash,
            encode_json($m)
        );


    #
    # Nur bei erfolgreichem Versand hochzählen.
    #
    $hash->{TxMsgID}++
        if $r;


    return $r;
}


##############################################
# Protocol / Initial Handshake
##############################################

sub HomeConnectLocal_InitialHandshake {
    my ($hash, $d) = @_;

    return
        if !$d ||
           ref($d) ne 'HASH' ||
           !$d->{resource};

    my $n =
        $hash->{NAME};

    my $r =
        $d->{resource};

    my $a =
        $d->{action} // "";

    my $ct =
        $hash->{ConnectionType}
        // uc(
            AttrVal(
                $n,
                "connectionType",
                "TLS"
            )
        );


    #
    # =========================================================
    # /ei/initialValues
    # =========================================================
    #
    if (
        $r eq "/ei/initialValues" &&
        $a eq "POST"
    ) {

        my $sid =
            $d->{sID};

        my $mid =
            $d->{msgID};

        my $ed =
            (
                ref($d->{data}) eq 'ARRAY' &&
                @{$d->{data}} &&
                ref($d->{data}[0]) eq 'HASH'
            )
            ? $d->{data}[0]{edMsgID}
            : undef;

        if (
            !defined($sid) ||
            !defined($mid) ||
            !defined($ed)
        ) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "/ei/initialValues unvollständig.";

            return;
        }

        $hash->{SessionID} =
            $sid;

        $hash->{TxMsgID} =
            $ed;

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "/ei/initialValues empfangen: "
            . "sID=$sid "
            . "msgID=$mid "
            . "edMsgID=$ed "
            . "connectionType=$ct";


        #
        # =====================================================
        # initialValues RESPONSE
        # =====================================================
        #

        my $ok;

        if ($ct eq "AES") {

            #
            # Exakte JSON-Feldreihenfolge für AES.
            #
            my $json =
                  '{"sID":'
                . (0 + $sid)
                . ',"msgID":'
                . (0 + $mid)
                . ',"resource":"/ei/initialValues"'
                . ',"version":2'
                . ',"action":"RESPONSE"'
                . ',"data":[{'
                . '"deviceType":"Application",'
                . '"deviceName":"Homeassistant",'
                . '"deviceID":'
                . encode_json(
                    $hash->{DeviceID}
                )
                . '}]}';

            $ok =
                HomeConnectLocal_SendRaw(
                    $hash,
                    $json
                );
        }
        else {

            #
            # TLS unverändert über JSON::PP.
            #
            my $response = {
                sID      => 0 + $sid,
                msgID    => 0 + $mid,
                resource => "/ei/initialValues",
                version  => 2,
                action   => "RESPONSE",
                data     => [
                    {
                        deviceType => "Application",
                        deviceName => "Homeassistant",
                        deviceID   => $hash->{DeviceID}
                    }
                ]
            };

            $ok =
                HomeConnectLocal_SendJSON(
                    $hash,
                    $response
                );
        }

        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "initialValues RESPONSE "
                . "konnte nicht gesendet werden.";

            return;
        }

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "initialValues RESPONSE gesendet.";


        #
        # =====================================================
        # AES
        # =====================================================
        #
        if ($ct eq "AES") {

            Log3 $n, 5,
                "HomeConnectLocal ($n) - "
                . "AES Handshake: sende /ci/services "
                . "in Referenz-JSON-Reihenfolge";

            my $json =
                  '{"sID":'
                . (0 + $sid)
                . ',"msgID":'
                . (0 + $ed)
                . ',"resource":"/ci/services"'
                . ',"version":1'
                . ',"action":"GET"}';

            my $services_ok =
                HomeConnectLocal_SendRaw(
                    $hash,
                    $json
                );

            if (!$services_ok) {

                Log3 $n, 3,
                    "HomeConnectLocal ($n) - "
                    . "AES /ci/services konnte "
                    . "nicht gesendet werden.";

                return;
            }

            $hash->{TxMsgID} =
                $ed + 1;

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "aes_wait_services",
                1
            );

            return;
        }


        #
        # =====================================================
        # TLS
        # =====================================================
        #
        # FUNKTIONIERENDEN TLS-PFAD NICHT VERÄNDERN.
        #

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ci/services";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ci/services",
            1,
            "GET"
        );


        my $nonce =
            encode_base64(
                HomeConnectLocal_RandomBytes(
                    32
                ),
                ""
            );

        $nonce =~
            tr!+/!-_!;

        $nonce =~
            s/=+$//;


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ci/authentication";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ci/authentication",
            2,
            "GET",
            {
                nonce => $nonce
            }
        );


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ci/info";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ci/info",
            2,
            "GET"
        );


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /iz/info";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/iz/info",
            1,
            "GET"
        );


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ni/info";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ni/info",
            1,
            "GET"
        );


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ei/deviceReady";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ei/deviceReady",
            2,
            "NOTIFY"
        );


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ro/allDescriptionChanges";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ro/allDescriptionChanges",
            1,
            "GET"
        );


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Sende /ro/allMandatoryValues";

        HomeConnectLocal_SendProtocol(
            $hash,
            "/ro/allMandatoryValues",
            1,
            "GET"
        );


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "initializing",
            1
        );

        return;
    }


    #
    # =========================================================
    # AES /ci/registeredDevices
    # =========================================================
    #
    if (
        $ct eq "AES" &&
        $r eq "/ci/registeredDevices" &&
        $a eq "NOTIFY"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /ci/registeredDevices empfangen.";

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "registeredDevices",
            encode_json($d),
            1
        );

        if (
            ref($d->{data}) eq 'ARRAY'
        ) {

            for my $dev (
                @{$d->{data}}
            ) {

                next
                    if ref($dev) ne 'HASH';

                next
                    if !defined(
                        $dev->{deviceID}
                    );

                if (
                    $dev->{deviceID} eq
                    $hash->{DeviceID}
                ) {

                    Log3 $n, 5,
                        "HomeConnectLocal ($n) - "
                        . "AES eigene Application gefunden: "
                        . "deviceID=$dev->{deviceID}, "
                        . "connected="
                        . (
                            $dev->{connected}
                            ? 1
                            : 0
                        );

                    last;
                }
            }
        }

        return;
    }


    #
    # =========================================================
    # /ci/services RESPONSE
    # =========================================================
    #
    if (
        $r eq "/ci/services" &&
        $a eq "RESPONSE"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "/ci/services empfangen.";

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "services",
            encode_json($d),
            1
        );


        #
        # TLS:
        # Die weiteren Requests wurden im funktionierenden
        # TLS-Pfad bereits nach initialValues versendet.
        #
        if ($ct ne "AES") {
            return;
        }


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /ci/services RESPONSE erfolgreich.";


        my $sid =
            $hash->{SessionID};

        my $mid =
            $hash->{TxMsgID};


        if (
            !defined($sid) ||
            !defined($mid)
        ) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ci/authentication nicht möglich: "
                . "SessionID oder TxMsgID fehlt.";

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "aes_authentication_error",
                1
            );

            return;
        }


        my $nonce =
            encode_base64(
                HomeConnectLocal_RandomBytes(
                    32
                ),
                ""
            );

        $nonce =~
            tr!+/!-_!;

        $nonce =~
            s/=+$//;

        $HomeConnectLocal_Private{$hash->{NAME}}{AES_AUTH_NONCE} =
            $nonce;


        my $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/ci/authentication"'
            . ',"version":2'
            . ',"action":"GET"'
            . ',"data":[{"nonce":'
            . encode_json(
                $nonce
            )
            . '}]}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES Handshake: sende /ci/authentication "
            . "msgID=$mid";


        my $auth_ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$auth_ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ci/authentication konnte "
                . "nicht gesendet werden.";

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "aes_authentication_error",
                1
            );

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "aes_wait_authentication",
            1
        );


        return;
    }


    #
    # =========================================================
    # AES /ci/authentication RESPONSE
    # =========================================================
    #
    if (
        $ct eq "AES" &&
        $r eq "/ci/authentication" &&
        $a eq "RESPONSE"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /ci/authentication RESPONSE erfolgreich.";

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "authentication",
            encode_json($d),
            1
        );


        my $sid =
            $hash->{SessionID};

        my $mid =
            $hash->{TxMsgID};


        my $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/ci/info"'
            . ',"version":2'
            . ',"action":"GET"}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES Handshake: sende /ci/info "
            . "msgID=$mid";


        my $ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ci/info konnte nicht gesendet werden.";

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "aes_wait_ci_info",
            1
        );


        return;
    }


    #
    # =========================================================
    # AES /ci/info RESPONSE
    # =========================================================
    #
    if (
        $ct eq "AES" &&
        $r eq "/ci/info" &&
        $a eq "RESPONSE"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /ci/info RESPONSE erfolgreich.";

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "ci_info",
            encode_json($d),
            1
        );


        my $sid =
            $hash->{SessionID};

        my $mid =
            $hash->{TxMsgID};


        my $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/iz/info"'
            . ',"version":1'
            . ',"action":"GET"}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES Handshake: sende /iz/info "
            . "msgID=$mid";


        my $ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /iz/info konnte nicht gesendet werden.";

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "aes_wait_iz_info",
            1
        );


        return;
    }


     #
    # =========================================================
    # AES /iz/info RESPONSE
    #
    # Referenz:
    # Nach /iz/info kommt zuerst /ei/deviceReady.
    # Erst DANACH wird /ni/info abgefragt.
    # =========================================================
    #
    if (
        $ct eq "AES" &&
        $r eq "/iz/info" &&
        $a eq "RESPONSE"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /iz/info RESPONSE erfolgreich.";

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "iz_info",
            encode_json($d),
            1
        );


        my $sid =
            $hash->{SessionID};

        my $mid =
            $hash->{TxMsgID};


        #
        # =====================================================
        # /ei/deviceReady
        #
        # Aktuelle homeconnect_websocket Referenz:
        #
        # /iz/info
        #     ↓
        # /ei/deviceReady NOTIFY
        #     ↓
        # /ni/info
        # =====================================================
        #

        my $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/ei/deviceReady"'
            . ',"version":2'
            . ',"action":"NOTIFY"}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES Handshake: sende /ei/deviceReady "
            . "VOR /ni/info "
            . "msgID=$mid";


        my $ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ei/deviceReady konnte "
                . "nicht gesendet werden.";

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        #
        # deviceReady ist NOTIFY.
        #
        # Darauf wird KEINE RESPONSE erwartet.
        #
        # Direkt danach folgt laut Referenz /ni/info.
        #

        $mid =
            $hash->{TxMsgID};


        $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/ni/info"'
            . ',"version":1'
            . ',"action":"GET"}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES Handshake: sende /ni/info "
            . "NACH deviceReady "
            . "msgID=$mid";


        $ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ni/info konnte "
                . "nicht gesendet werden.";

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "aes_wait_ni_info",
            1
        );


        return;
    }

    #
    # =========================================================
    # AES /ni/info RESPONSE
    #
    # Der eigentliche AES-Handshake ist jetzt abgeschlossen.
    #
    # Reihenfolge:
    #
    # /iz/info RESPONSE
    #      ↓
    # /ei/deviceReady NOTIFY
    #      ↓
    # /ni/info GET
    #      ↓
    # /ni/info RESPONSE
    #      ↓
    # /ro/allDescriptionChanges GET
    # =========================================================
    #
    if (
        $ct eq "AES" &&
        $r eq "/ni/info" &&
        $a eq "RESPONSE"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /ni/info RESPONSE erfolgreich.";

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "ni_info",
            encode_json($d),
            1
        );


        #
        # Falls /ni/info selbst einen Fehlercode enthält,
        # hier zunächst sauber protokollieren.
        #
        if (
            exists($d->{code}) &&
            defined($d->{code}) &&
            $d->{code} != 0
        ) {

            Log3 $n, 5,
                "HomeConnectLocal ($n) - "
                . "AES /ni/info Fehler: "
                . "code=$d->{code}";

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "last_error",
                encode_json($d),
                1
            );

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "aes_ni_info_error_" . $d->{code},
                1
            );

            return;
        }


        Log3 $n, 2,
            "HomeConnectLocal ($n) - "
            . "AES Handshake erfolgreich abgeschlossen.";


        #
        # =====================================================
        # Jetzt Remote-Object-Beschreibung abfragen.
        #
        # WICHTIG:
        # deviceReady wird hier NICHT erneut gesendet.
        # =====================================================
        #

        my $sid =
            $hash->{SessionID};

        my $mid =
            $hash->{TxMsgID};


        if (
            !defined($sid) ||
            !defined($mid)
        ) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "/ro/allDescriptionChanges nicht möglich: "
                . "SessionID oder TxMsgID fehlt.";

            return;
        }


        my $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/ro/allDescriptionChanges"'
            . ',"version":1'
            . ',"action":"GET"}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES: sende /ro/allDescriptionChanges "
            . "msgID=$mid";


        my $ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ro/allDescriptionChanges konnte "
                . "nicht gesendet werden.";

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "aes_description_changes_error",
                1
            );

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "aes_wait_description_changes",
            1
        );


        return;
    }

    #
    # =========================================================
    # AES /ro/allDescriptionChanges RESPONSE
    #
    # Bleibt für spätere Tests erhalten.
    # Im aktuellen AES-Test wird dieser Block nicht erreicht.
    # =========================================================
    #
    if (
        $ct eq "AES" &&
        $r eq "/ro/allDescriptionChanges" &&
        $a eq "RESPONSE"
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES /ro/allDescriptionChanges "
            . "RESPONSE erfolgreich.";

        HomeConnectLocal_ParseDescriptionChanges($hash, $d);
        HomeConnectLocal_BuildSetMap($hash);

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "descriptionChanges",
            encode_json($d),
            1
        );


        my $sid =
            $hash->{SessionID};

        my $mid =
            $hash->{TxMsgID};


        my $json =
              '{"sID":'
            . (0 + $sid)
            . ',"msgID":'
            . (0 + $mid)
            . ',"resource":"/ro/allMandatoryValues"'
            . ',"version":1'
            . ',"action":"GET"}';


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "AES Handshake: sende /ro/allMandatoryValues "
            . "msgID=$mid";


        my $ok =
            HomeConnectLocal_SendRaw(
                $hash,
                $json
            );


        if (!$ok) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "AES /ro/allMandatoryValues konnte "
                . "nicht gesendet werden.";

            return;
        }


        $hash->{TxMsgID} =
            $mid + 1;


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "aes_wait_mandatory_values",
            1
        );


        return;
    }


    #
    # =========================================================
    # registeredDevices allgemein / TLS
    # =========================================================
    #
    if (
        $r eq "/ci/registeredDevices" &&
        (
            $a eq "RESPONSE" ||
            $a eq "NOTIFY"
        )
    ) {

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "registeredDevices",
            encode_json($d),
            1
        );

        return;
    }


    #
    # =========================================================
    # Weitere Antworten
    # =========================================================
    #
    my %rr = (
        "/ci/authentication"        => "authentication",
        "/ci/info"                  => "ci_info",
        "/iz/info"                  => "iz_info",
        "/ni/info"                  => "ni_info",
        "/ei/deviceReady"           => "deviceReady",
        "/ro/allDescriptionChanges" => "descriptionChanges"
    );

    if (
        exists($rr{$r}) &&
        (
            $a eq "RESPONSE" ||
            $a eq "NOTIFY"
        )
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Antwort empfangen: "
            . "resource=$r "
            . "action=$a";

        if ($r eq "/ro/allDescriptionChanges") {
            HomeConnectLocal_ParseDescriptionChanges($hash, $d);
            HomeConnectLocal_BuildSetMap($hash);
        }

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            $rr{$r},
            encode_json($d),
            1
        );

        return;
    }


    #
    # =========================================================
    # Values
    # =========================================================
    #
    if (
        (
            $r eq "/ro/allMandatoryValues" ||
            $r eq "/ro/values"
        )
        &&
        (
            $a eq "RESPONSE" ||
            $a eq "NOTIFY"
        )
    ) {

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Werte empfangen: "
            . "resource=$r "
            . "action=$a";


        #
        # Komplette Antwort für Debugging anzeigen
        #
        # Temporary protocol diagnostics at loglevel 2.  This intentionally
        # logs both the complete decoded message and its data section so we
        # can compare appliance-generated NOTIFYs with our POST response.
        my $ro_data_json;
        eval { $ro_data_json = encode_json($d); 1; }
            or $ro_data_json = "<encode_json data failed: $@>";

        Log3 $n, 5,
            "HomeConnectLocal ($n) - RO DATA $a: "
            . $ro_data_json;


        #
        # =====================================================
        # Protokollfehler innerhalb einer RESPONSE erkennen
        #
        # Beispiel vom Kochfeld:
        #
        # {
        #   "action":"RESPONSE",
        #   "resource":"/ro/allMandatoryValues",
        #   "code":403
        # }
        #
        # Das darf NICHT als erfolgreiche Initialisierung
        # behandelt werden.
        # =====================================================
        #
        if (
            exists($d->{code}) &&
            defined($d->{code}) &&
            $d->{code} != 0
        ) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "Request $r abgelehnt: "
                . "code=$d->{code}";


            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "last_error",
                encode_json($d),
                1
            );


            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "protocol_error_" . $d->{code},
                1
            );


            return;
        }


        #
        # =====================================================
        # Erfolgreiche Values-Antwort speichern
        # =====================================================
        #
        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            $r eq "/ro/allMandatoryValues"
                ? "mandatoryValues"
                : "values",
            encode_json($d),
            1
        );


        #
        # UID/Value-Mapping erfolgt zentral in
        # HomeConnectLocal_ProcessPayload().
        # Dadurch wird jedes Reading nur einmal aktualisiert.


        #
        # =====================================================
        # Erst eine ERFOLGREICHE allMandatoryValues RESPONSE
        # setzt das Gerät auf connected.
        # =====================================================
        #
        if (
            $r eq "/ro/allMandatoryValues"
        ) {

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "connected",
                1
            );


            Log3 $n, 2,
                "HomeConnectLocal ($n) - "
                . "Initialisierung abgeschlossen.";
        }


        return;
    }


    #
    # =========================================================
    # Protocol Error
    # =========================================================
    #
    if (
        exists(
            $d->{code}
        )
    ) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "Protokollfehler: "
            . encode_json($d);

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "last_error",
            encode_json($d),
            1
        );

        return;
    }


    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "Unbehandelte Nachricht: "
        . encode_json($d);

    return;
}
##############################################
# Process JSON Payload
##############################################

sub HomeConnectLocal_ProcessPayload {
    my ($hash, $payload) = @_;

    my $n =
        $hash->{NAME};

    my $d;


    eval {
        $d =
            decode_json(
                $payload
            );
    };


    if ($@) {

        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "JSON Decode Fehler: $@";

        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "Payload: $payload";

        return;
    }


    return
        if ref($d) ne 'HASH';


    Log3 $n, 5,
        "HomeConnectLocal ($n) - "
        . "RX resource="
        . ($d->{resource} // "-")
        . " action="
        . ($d->{action} // "-")
        . " msgID="
        . (
            defined(
                $d->{msgID}
            )
            ? $d->{msgID}
            : "-"
        );


    if (
        exists(
            $d->{resource}
        )
    ) {

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "last_resource",
            $d->{resource},
            1
        );
    }


    if (
        exists(
            $d->{action}
        )
    ) {

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "last_action",
            $d->{action},
            1
        );
    }


    #
    # Mapping
    #
    if (
        ref($d->{data}) eq 'ARRAY'
    ) {

        for my $i (
            @{$d->{data}}
        ) {

            next
                if ref($i) ne 'HASH';


            if (
                exists(
                    $i->{uid}
                ) &&
                exists(
                    $i->{value}
                )
            ) {

                HomeConnectLocal_UpdateMappedValue(
                    $hash,
                    $i->{uid},
                    $i->{value}
                );
            }
        }
    }


    #
    # Protokoll
    #
    HomeConnectLocal_InitialHandshake(
        $hash,
        $d
    );


    return;
}


##############################################
# Read
##############################################

sub HomeConnectLocal_Read {
    my ($hash) = @_;

    my $n =
        $hash->{NAME};

    my $s =
        $hash->{CD};

    return
        if !$s;


    my $buf =
        '';


    my $rd =
        sysread(
            $s,
            $buf,
            65536
        );


    if (!defined($rd)) {

        return
            if $!{EAGAIN} ||
               $!{EWOULDBLOCK};


        Log3 $n, 3,
            "HomeConnectLocal ($n) - "
            . "Socket Lesefehler: $!";


        HomeConnectLocal_Close(
            $hash
        );

        return;
    }


    if ($rd == 0) {

        Log3 $n, 2,
            "HomeConnectLocal ($n) - "
            . "Socket geschlossen.";


        HomeConnectLocal_Close(
            $hash
        );

        return;
    }


    $hash->{PARTIAL} .=
        $buf;


    #
    # ==========================================
    # HTTP -> WebSocket
    # ==========================================
    #
    if (
        $hash->{WSHandshake}
    ) {

        my $e =
            index(
                $hash->{PARTIAL},
                "\r\n\r\n"
            );


        return
            if $e < 0;


        my $h =
            substr(
                $hash->{PARTIAL},
                0,
                $e + 4
            );


        substr(
            $hash->{PARTIAL},
            0,
            $e + 4
        ) = "";


        if (
            $h !~
            m/^HTTP\/1\.[01]\s+101\b/im
        ) {

            Log3 $n, 3,
                "HomeConnectLocal ($n) - "
                . "WebSocket Handshake "
                . "fehlgeschlagen: $h";


            HomeConnectLocal_Close(
                $hash
            );

            return;
        }


        $hash->{WSHandshake} =
            0;


        #
        # Fragment-State zurücksetzen.
        #
        delete $hash->{WS_FRAGMENT_DATA};
        delete $hash->{WS_FRAGMENT_OPCODE};


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "websocket_connected",
            1
        );


        Log3 $n, 2,
            "HomeConnectLocal ($n) - "
            . "WebSocket Verbindung "
            . "erfolgreich geöffnet.";
    }


    #
    # ==========================================
    # WebSocket Frames
    # ==========================================
    #
    while (
        length(
            $hash->{PARTIAL}
        ) >= 2
    ) {

        my $b1 =
            ord(
                substr(
                    $hash->{PARTIAL},
                    0,
                    1
                )
            );


        my $b2 =
            ord(
                substr(
                    $hash->{PARTIAL},
                    1,
                    1
                )
            );


        #
        # FIN-Bit
        #
        my $fin =
            ($b1 & 0x80)
            ? 1
            : 0;


        #
        # Opcode
        #
        my $op =
            $b1 & 0x0f;


        my $masked =
            $b2 & 0x80;


        my $pl =
            $b2 & 0x7f;


        my $pos =
            2;


        #
        # Extended Payload Length 16 Bit
        #
        if ($pl == 126) {

            last
                if length(
                    $hash->{PARTIAL}
                ) < $pos + 2;


            $pl =
                unpack(
                    "n",
                    substr(
                        $hash->{PARTIAL},
                        $pos,
                        2
                    )
                );


            $pos +=
                2;

        }

        #
        # Extended Payload Length 64 Bit
        #
        elsif ($pl == 127) {

            last
                if length(
                    $hash->{PARTIAL}
                ) < $pos + 8;


            my (
                $hi,
                $lo
            ) =
                unpack(
                    "N2",
                    substr(
                        $hash->{PARTIAL},
                        $pos,
                        8
                    )
                );


            $pl =
                $hi * 4294967296
                + $lo;


            $pos +=
                8;
        }


        #
        # Mask
        #
        my $mask =
            '';


        if ($masked) {

            last
                if length(
                    $hash->{PARTIAL}
                ) < $pos + 4;


            $mask =
                substr(
                    $hash->{PARTIAL},
                    $pos,
                    4
                );


            $pos +=
                4;
        }


        #
        # Auf vollständigen Frame warten.
        #
        last
            if length(
                $hash->{PARTIAL}
            ) < $pos + $pl;


        #
        # Payload entnehmen.
        #
        my $p =
            substr(
                $hash->{PARTIAL},
                $pos,
                $pl
            );


        #
        # Frame aus Empfangspuffer entfernen.
        #
        substr(
            $hash->{PARTIAL},
            0,
            $pos + $pl
        ) = "";


        Log3 $n, 5,
            "HomeConnectLocal ($n) - "
            . "WS RX frame "
            . "FIN=$fin "
            . "opcode="
            . sprintf("0x%X", $op)
            . " payload=$pl";


        #
        # ==========================================
        # Unmask
        # ==========================================
        #
        if ($masked) {

            my $u =
                '';


            for (
                my $i = 0;
                $i < $pl;
                $i++
            ) {

                $u .=
                    chr(
                        ord(
                            substr(
                                $p,
                                $i,
                                1
                            )
                        )
                        ^
                        ord(
                            substr(
                                $mask,
                                $i % 4,
                                1
                            )
                        )
                    );
            }


            $p =
                $u;
        }


        #
        # ==========================================
        # CLOSE
        # ==========================================
        #
        if ($op == 0x8) {

            my $code =
                "";

            my $reason =
                "";


            if (
                length($p) >= 2
            ) {

                $code =
                    unpack(
                        "n",
                        substr(
                            $p,
                            0,
                            2
                        )
                    );
            }


            if (
                length($p) > 2
            ) {

                $reason =
                    substr(
                        $p,
                        2
                    );
            }


            Log3 $n, 2,
                "HomeConnectLocal ($n) - "
                . "WebSocket CLOSE empfangen"
                . (
                    $code ne ""
                    ? " code=$code"
                    : ""
                )
                . (
                    $reason ne ""
                    ? " reason=$reason"
                    : ""
                );


            HomeConnectLocal_Close(
                $hash
            );

            return;
        }


        #
        # ==========================================
        # PING
        # ==========================================
        #
        if ($op == 0x9) {

            my $pong =
                HomeConnectLocal_WSFrame_Control(
                    0xA,
                    $p
                );


            syswrite(
                $s,
                $pong
            ) if defined($pong);


            next;
        }


        #
        # ==========================================
        # PONG
        # ==========================================
        #
        if ($op == 0xA) {

            next;
        }


        #
        # ==========================================
        # WebSocket Fragmentierung
        # ==========================================
        #


        #
        # Neuer Text- oder Binary-Frame.
        #
        if (
            $op == 0x1 ||
            $op == 0x2
        ) {

            #
            # FIN=0:
            # Beginn einer fragmentierten Nachricht.
            #
            if (!$fin) {

                $hash->{WS_FRAGMENT_OPCODE} =
                    $op;

                $hash->{WS_FRAGMENT_DATA} =
                    $p;


                Log3 $n, 5,
                    "HomeConnectLocal ($n) - "
                    . "WS Fragment gestartet "
                    . "opcode="
                    . sprintf("0x%X", $op)
                    . " bytes="
                    . length($p);


                next;
            }

            #
            # FIN=1:
            # Vollständige Nachricht in einem Frame.
            #
        }


        #
        # Continuation Frame
        #
        elsif ($op == 0x0) {

            #
            # Continuation ohne vorherigen Start.
            #
            if (
                !exists(
                    $hash->{WS_FRAGMENT_OPCODE}
                )
            ) {

                Log3 $n, 5,
                    "HomeConnectLocal ($n) - "
                    . "WS Continuation ohne "
                    . "Fragment-Start.";

                next;
            }


            $hash->{WS_FRAGMENT_DATA} .=
                $p;


            Log3 $n, 5,
                "HomeConnectLocal ($n) - "
                . "WS Fragment fortgesetzt "
                . "bytes="
                . length(
                    $hash->{WS_FRAGMENT_DATA}
                )
                . " FIN=$fin";


            #
            # Noch nicht fertig.
            #
            next
                if !$fin;


            #
            # Letztes Fragment:
            # komplette Nachricht herstellen.
            #
            $p =
                $hash->{WS_FRAGMENT_DATA};

            $op =
                $hash->{WS_FRAGMENT_OPCODE};


            delete
                $hash->{WS_FRAGMENT_DATA};

            delete
                $hash->{WS_FRAGMENT_OPCODE};


            Log3 $n, 5,
                "HomeConnectLocal ($n) - "
                . "WS fragmentierte Nachricht "
                . "vollständig "
                . "opcode="
                . sprintf("0x%X", $op)
                . " bytes="
                . length($p);
        }


        #
        # Andere Data-Opcodes ignorieren.
        #
        else {

            Log3 $n, 5,
                "HomeConnectLocal ($n) - "
                . "WS unbekannter Opcode "
                . sprintf("0x%X", $op);

            next;
        }


        #
        # ==========================================
        # Nur Text / Binary
        # ==========================================
        #
        next
            if $op != 0x1 &&
               $op != 0x2;


        #
        # ==========================================
        # AES
        # ==========================================
        #
        if (
            ($hash->{ConnectionType} // "TLS")
            eq "AES"
        ) {

            #
            # AES muss Binary sein.
            #
            next
                if $op != 0x2;


            Log3 $n, 5,
                "HomeConnectLocal ($n) - "
                . "AES vollständige WS Nachricht "
                . "bytes="
                . length($p);


            $p =
                HomeConnectLocal_AESDecrypt(
                    $hash,
                    $p
                );


            next
                if !defined($p);
        }


        #
        # ==========================================
        # JSON Payload
        # ==========================================
        #
        HomeConnectLocal_ProcessPayload(
            $hash,
            $p
        );
    }


    return;
}

##############################################
# Close
##############################################

sub HomeConnectLocal_Close {
    my ($hash) = @_;

    my $n =
        $hash->{NAME};


    if (
        $hash->{CD}
    ) {

        close(
            $hash->{CD}
        );

        delete
            $hash->{CD};
    }


    delete
        $main::selectlist{$n};

    delete
        $hash->{FD};

    delete
        $hash->{WSHandshake};

    delete
        $hash->{WS_FRAGMENT_DATA};

    delete
        $hash->{WS_FRAGMENT_OPCODE};


    $hash->{PARTIAL} =
        "";


    HomeConnectLocal_ReadingsSingleUpdate(
        $hash,
        "state",
        "closed",
        1
    );


    InternalTimer(
        time() + 10,
        "HomeConnectLocal_Connect",
        $hash,
        0
    );


    return;
}


##############################################
# Undefine
##############################################

sub HomeConnectLocal_Undefine {
    my ($hash) = @_;


    RemoveInternalTimer(
        $hash
    );


    if (
        $hash->{CD}
    ) {

        close(
            $hash->{CD}
        );

        delete
            $hash->{CD};
    }


    delete
        $main::selectlist{
            $hash->{NAME}
        };


    delete
        $hash->{FD};

    delete
        $hash->{WSHandshake};

    delete
        $hash->{WS_FRAGMENT_DATA};

    delete
        $hash->{WS_FRAGMENT_OPCODE};


    $hash->{PARTIAL} =
        "";

    delete $HomeConnectLocal_Private{$hash->{NAME}};

    return undef;
}


##############################################
# Set
##############################################
# Automatic startup after FHEM INITIALIZED (v31)
##############################################

sub HomeConnectLocal_Notify {
    my ($hash, $dev) = @_;
    return undef if !$hash || !$dev || ($dev->{NAME} // '') ne 'global';
    my $events = deviceEvents($dev, 1);
    return undef if !$events;

    for my $event (@$events) {
        next if !defined($event) || $event ne 'INITIALIZED';
        my $name = $hash->{NAME};
        return undef if !$name || AttrVal($name, 'disable', 0);

        # Clean up data exposed by older versions as soon as FHEM is initialized.
        delete @{$hash}{grep { /^AES_/ } keys %{$hash}};
        HomeConnectLocal_ApplyRawReadingVisibility($hash);

        # Run shortly after INITIALIZED so all attributes and FHEM state are
        # fully available. The callback deliberately performs reloadMapping
        # first and connect second.
        InternalTimer(gettimeofday() + 0.5, 'HomeConnectLocal_AutoStart', $hash, 0);
        last;
    }
    return undef;
}

sub HomeConnectLocal_AutoStart {
    my ($hash) = @_;
    return if !$hash;
    my $name = $hash->{NAME};
    return if !$name || AttrVal($name, 'disable', 0);

    Log3 $name, 5, "HomeConnectLocal ($name) - AUTO START: reloadMapping -> connect";
    HomeConnectLocal_LoadMapping($hash);
    return if AttrVal($name, 'disable', 0);
    HomeConnectLocal_Connect($hash);
    return;
}

##############################################

sub HomeConnectLocal_Set {
    my (
        $hash,
        @a
    ) = @_;


    my $n =
        $hash->{NAME};


    return
        "Unknown argument, choose one of " . HomeConnectLocal_SetList($hash)
        if @a < 2;


    if (
        $a[1] eq "connect"
    ) {

        RemoveInternalTimer(
            $hash
        );


        HomeConnectLocal_Connect(
            $hash
        );


        return undef;
    }


    if (
        $a[1] eq "reloadMapping"
    ) {

        HomeConnectLocal_LoadMapping(
            $hash
        );


        return undef;
    }


    if (
        $a[1] eq "disconnect"
    ) {

        RemoveInternalTimer(
            $hash
        );


        HomeConnectLocal_Undefine(
            $hash
        );


        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "state",
            "disconnected",
            1
        );


        return undef;
    }


    # v20: private command used by HomeConnectLocal.js. It is intentionally
    # omitted from SetList so normal FHEMWEB users do not see an implementation
    # detail. During the session automatic page reloads are deferred.
    if ($a[1] eq "programConfigSession") {
        return "Usage: set $n programConfigSession begin|end" if @a < 3;
        if (lc($a[2]) eq 'begin') {
            $hash->{HC_CONFIG_SESSION} = 1;
            delete $hash->{HC_CONFIG_REFRESH_PENDING};
            return undef;
        }
        if (lc($a[2]) eq 'end') {
            delete $hash->{HC_CONFIG_SESSION};
            my $pending = delete $hash->{HC_CONFIG_REFRESH_PENDING};
            HomeConnectLocal_RefreshFhemWebSetListIfChanged($hash, 1) if $pending;
            return undef;
        }
        return "Usage: set $n programConfigSession begin|end";
    }

    if ($a[1] eq "program") {
        return "Usage: set $n program <program>"
            if @a < 3;

        my @program_candidates = map { $_->{name} }
            grep { ref($_) eq 'HASH' && defined($_->{name}) } @{ $hash->{HC_PROGRAMS} || [] };
        $a[2] = HomeConnectLocal_ResolveSetToken($hash, 'program', $a[2], \@program_candidates);
        my $p = HomeConnectLocal_FindProgram($hash, $a[2]);
        return "Unknown program '$a[2]', choose one of "
             . join(',', map { $_->{name} } @{ $hash->{HC_PROGRAMS} || [] })
            if !defined($p);

        my $root = HomeConnectLocal_FindProgramRoot($hash, 'selectedProgram');

        Log3 $n, 5,
            "HomeConnectLocal ($n) - PROGRAM TEST: requested='$p->{name}', "
          . "programUID=$p->{uid}, programFeature=$p->{feature}"
          . (defined($root)
                ? ", selectedProgramUID=$root->{uid}, selectedProgramFeature=$root->{feature}"
                : ", selectedProgram=<not found>");

        return "SelectedProgram wurde im XML-Mapping nicht gefunden."
            if !defined($root);

        # XML-UIDs sind Hexwerte (z.B. 0101 / 2004). Im lokalen
        # Protokoll werden die entsprechenden numerischen Werte benutzt.
        my $selected_uid = hex($root->{uid});
        my $program_uid  = hex($p->{uid});

        # hcpy uses the dedicated program resource instead of /ro/values.
        # HomeConnectLocal_SendProtocol wraps this hash in the protocol's
        # data array, resulting in:
        #   "data":[{"program":8195}]
        my $payload = {
            program => 0 + $program_uid
        };

        Log3 $n, 5,
            "HomeConnectLocal ($n) - PROGRAM SEND: "
          . "resource=/ro/selectedProgram action=POST "
          . "xmlSelectedUID=$root->{uid} protocolUID=$selected_uid "
          . "xmlProgramUID=$p->{uid} protocolValue=$program_uid "
          . "data=" . encode_json($payload);

        my $sent = HomeConnectLocal_SendProtocol(
            $hash,
            "/ro/selectedProgram",
            1,
            "POST",
            $payload
        );

        if (!$sent) {
            Log3 $n, 3,
                "HomeConnectLocal ($n) - PROGRAM SEND fehlgeschlagen: '$p->{name}'";
            return "Programm '$p->{name}' konnte nicht gesendet werden. "
                 . "Bitte Verbindung/Log pruefen.";
        }

        # A program change invalidates option choices from the previous
        # program. This prevents stale options being sent with another program.
        delete $hash->{HC_SELECTED_PROGRAM_OPTIONS};

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash,
            "selectedProgramCandidate",
            $p->{name},
            1
        );

        return undef;
    }

    # v28: FHEMWEB may submit translated SetList labels. Resolve them
    # back to the stable XML/protocol names before normal command handling.
    if (ref($hash->{HC_OPTION_BY_NAME}) eq 'HASH') {
        my @option_candidates = keys %{ $hash->{HC_OPTION_BY_NAME} };
        $a[1] = HomeConnectLocal_ResolveSetToken($hash, 'option', $a[1], \@option_candidates);
    }

    # v5: direct program option syntax:
    #   set <device> Temperature GC40
    #   set <device> SpinSpeed RPM1400
    #   set <device> ProgramMode WashingAndDrying
    #   set <device> DryingTarget CupboardDry
    # Boolean options also work as: set <device> Prewash on|off
    if (ref($hash->{HC_OPTION_BY_NAME}) eq 'HASH'
        && ref($hash->{HC_OPTION_BY_NAME}{$a[1]}) eq 'HASH') {

        my $option_name = $a[1];
        my $e = $hash->{HC_OPTION_BY_NAME}{$option_name};
        return "Usage: set $n $option_name <value>" if @a < 3;

        my $p = HomeConnectLocal_CurrentSelectedProgram($hash);
        return "Kein Programm ausgewaehlt. Bitte zuerst 'set $n program <Programm>' verwenden."
            if !defined($p);

        my %allowed = map { HomeConnectLocal_NormalizeHex($_) => 1 }
                      @{ $p->{optionUIDs} || [] };
        return "Option '$option_name' ist fuer Programm '$p->{name}' nicht verfuegbar."
            if !$allowed{ HomeConnectLocal_NormalizeHex($e->{uid}) };

        # Resolve the option metadata again in the selected-program context.
        # This is important after the automatic description refresh because
        # Temperature/SpinSpeed can switch to another subset enum.
        my $nu = HomeConnectLocal_NormalizeHex($e->{uid});
        $e = HomeConnectLocal_ProgramOptionContextMeta($hash, $p, $nu, $e);

        # v16: direct SETs must obey the same live access state as the menu.
        # Otherwise a hidden READ-only option could still be written manually.
        if ($e->{runtimeLiveContext}) {
            my $acc = lc($e->{access} // '');
            return "Option '$option_name' ist im aktuellen Programm nur lesbar."
                if $acc !~ /^(?:readwrite|writeonly)$/;
            return "Option '$option_name' ist im aktuellen Programm nicht verfuegbar."
                if defined($e->{available}) && lc("$e->{available}") eq 'false';
        }

        my $input = $a[2];
        my ($value, $display);
        # Runtime enumType is authoritative; XML enumerationType is fallback.
        my $enum_type = $e->{enumType} // $e->{enumerationType};

        if (defined($enum_type) && $enum_type ne '') {
            $enum_type = HomeConnectLocal_NormalizeHex($enum_type);
            my $ev = $hash->{Mapping}{EnumValues}{$enum_type};
            return "EnumValues fuer Option '$option_name' ($enum_type) fehlen."
                if ref($ev) ne 'HASH';

            # v15 validates against exactly the same context-sensitive values
            # that are shown in FHEMWEB.  ProgramMode additionally uses the
            # XML/runtime union described in ProgramModeMenuPairs().
            my @allowed_pairs = ($option_name eq 'ProgramMode')
                ? HomeConnectLocal_ProgramModeMenuPairs($hash, $e)
                : HomeConnectLocal_EnumMenuPairs($hash, $e);
            my @value_candidates = map { $_->[1] } @allowed_pairs;
            $input = HomeConnectLocal_ResolveSetToken($hash, 'value', $input, \@value_candidates);
            for my $pair (@allowed_pairs) {
                my ($numeric, $name) = @$pair;
                if (defined($name) && lc("$name") eq lc($input)) {
                    $value = 0 + $numeric;
                    $display = $name;
                    last;
                }
            }
            if (!defined($value)) {
                my @values = map { $_->[1] } @allowed_pairs;
                return "Ungueltiger Wert '$input' fuer '$option_name'. Erlaubt: "
                    . join(', ', @values);
            }
        }
        elsif (HomeConnectLocal_IsBooleanProgramOption($e)) {
            my @bool_candidates = qw(on off);
            $input = HomeConnectLocal_ResolveSetToken($hash, 'value', $input, \@bool_candidates);
            return "Ungueltiger Wert '$input' fuer '$option_name'. Erlaubt: on, off"
                if $input !~ /^(?:on|off|true|false|1|0)$/i;
            my $on = $input =~ /^(?:on|true|1)$/i ? 1 : 0;
            $value = $on ? JSON::PP::true : JSON::PP::false;
            $display = $on ? 'on' : 'off';
        }
        elsif ($input =~ /^-?(?:\d+(?:\.\d*)?|\.\d+)$/) {
            my $num = 0 + $input;
            return "Wert fuer '$option_name' ist zu klein (min=$e->{min})."
                if defined($e->{min}) && $num < $e->{min};
            return "Wert fuer '$option_name' ist zu gross (max=$e->{max})."
                if defined($e->{max}) && $num > $e->{max};
            $value = $num;
            $display = $input;
        }
        else {
            return "Option '$option_name' wird mit diesem Werttyp noch nicht unterstuetzt.";
        }

        $hash->{HC_SELECTED_PROGRAM_OPTIONS} ||= {};
        $hash->{HC_SELECTED_PROGRAM_OPTIONS}{$e->{uid}} = {
            uid => $e->{uid}, name => $option_name, feature => $e->{feature},
            value => $value, display => $display
        };

        HomeConnectLocal_ReadingsSingleUpdate(
            $hash, 'option_' . $option_name,
            defined($display) ? $display : $input, 1
        );

        my @options;
        for my $ouid (sort keys %{ $hash->{HC_SELECTED_PROGRAM_OPTIONS} }) {
            next if !$allowed{ HomeConnectLocal_NormalizeHex($ouid) };
            my $oe = $hash->{HC_SELECTED_PROGRAM_OPTIONS}{$ouid};
            next if ref($oe) ne 'HASH';
            push @options, { uid => 0 + hex($ouid), value => $oe->{value} };
        }

        my $device_type = $hash->{Mapping}{DeviceInfo}{type} // '';
        my ($resource, $payload);

        # WasherDryer exposes the selected-program options as READWRITE values
        # below optionList 161D.  Re-posting them as part of
        # /ro/selectedProgram only re-selects the program on these appliances.
        # Write the changed option itself through /ro/values instead.
        if (lc($device_type) eq 'washerdryer') {
            $resource = '/ro/values';
            $payload = { uid => 0 + hex($e->{uid}), value => $value };
        }
        else {
            # Keep the already proven dishwasher behaviour unchanged.
            $resource = '/ro/selectedProgram';
            $payload = { program => 0 + hex($p->{uid}), options => \@options };
        }

        Log3 $n, 5,
            "HomeConnectLocal ($n) - PROGRAM OPTION SEND: "
          . "resource=$resource action=POST program='$p->{name}' "
          . "option='$option_name' xmlOptionUID=$e->{uid} "
          . "protocolOptionUID=" . hex($e->{uid})
          . (defined($enum_type) ? " enumType=$enum_type" : '')
          . " input='$input' data=" . encode_json($payload);

        my $sent = HomeConnectLocal_SendProtocol(
            $hash, $resource, 1, 'POST', $payload
        );
        return "Option '$option_name' konnte nicht gesendet werden. Bitte Verbindung/Log pruefen."
            if !$sent;
        return undef;
    }

    # Compact option syntax:
    #   set <device> option <OptionName> on|off
    if ($a[1] eq "option") {
        return "Usage: set $n option <OptionName> on|off" if @a < 4;

        my $option_name = $a[2];
        my $e = (ref($hash->{HC_OPTION_BY_NAME}) eq 'HASH')
              ? $hash->{HC_OPTION_BY_NAME}{$option_name}
              : undef;

        return "Unknown option '$option_name'." if !HomeConnectLocal_IsBooleanProgramOption($e);

        {
            return "Usage: set $n option $option_name on|off"
                if $a[3] !~ /^(?:on|off)$/i;

            my $p = HomeConnectLocal_CurrentSelectedProgram($hash);
            return "Kein Programm ausgewaehlt. Bitte zuerst 'set $n program <Programm>' verwenden."
                if !defined($p);

            my %allowed = map { $_ => 1 } @{ $p->{optionUIDs} || [] };
            return "Option '$a[1]' ist fuer Programm '$p->{name}' nicht verfuegbar."
                if !$allowed{$e->{uid}};

            my $on = lc($a[3]) eq 'on' ? 1 : 0;

            $hash->{HC_SELECTED_PROGRAM_OPTIONS} ||= {};
            $hash->{HC_SELECTED_PROGRAM_OPTIONS}{$e->{uid}} = {
                uid     => $e->{uid},
                name    => $e->{setName},
                feature => $e->{feature},
                value   => $on
            };

            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "option_" . $e->{setName},
                $on ? "on" : "off",
                1
            );

            my @options;
            my %allowed_now = map { $_ => 1 } @{ $p->{optionUIDs} || [] };

            # Send all options currently selected for this program.  This
            # mirrors the appliance UI: changing an option immediately
            # reconfigures SelectedProgram and lets the appliance recalculate
            # duration/forecast values.
            for my $ouid (sort keys %{ $hash->{HC_SELECTED_PROGRAM_OPTIONS} }) {
                next if !$allowed_now{$ouid};
                my $oe = $hash->{HC_SELECTED_PROGRAM_OPTIONS}{$ouid};
                next if ref($oe) ne 'HASH';

                push @options, {
                    uid   => 0 + hex($ouid),
                    value => $oe->{value} ? JSON::PP::true : JSON::PP::false
                };
            }

            my $option_payload = {
                program => 0 + hex($p->{uid}),
                options => \@options
            };

            my $device_type = $hash->{Mapping}{DeviceInfo}{type} // '';
            my ($resource, $send_payload);
            if (lc($device_type) eq 'washerdryer') {
                $resource = '/ro/values';
                $send_payload = {
                    uid   => 0 + hex($e->{uid}),
                    value => $on ? JSON::PP::true : JSON::PP::false
                };
            }
            else {
                $resource = '/ro/selectedProgram';
                $send_payload = $option_payload;
            }

            Log3 $n, 5,
                "HomeConnectLocal ($n) - PROGRAM OPTION SEND: "
              . "resource=$resource action=POST "
              . "program='$p->{name}' option='$e->{setName}' "
              . "xmlOptionUID=$e->{uid} protocolOptionUID=" . hex($e->{uid})
              . " value=" . ($on ? "true" : "false")
              . " data=" . encode_json($send_payload);

            my $sent = HomeConnectLocal_SendProtocol(
                $hash,
                $resource,
                1,
                "POST",
                $send_payload
            );

            if (!$sent) {
                Log3 $n, 3,
                    "HomeConnectLocal ($n) - PROGRAM OPTION SEND fehlgeschlagen: "
                  . "'$e->{setName}'";
                return "Option '$e->{setName}' konnte nicht gesendet werden. "
                     . "Bitte Verbindung/Log pruefen.";
            }

            return undef;
        }
    }

    if (ref($hash->{HC_SETMAP}) eq 'HASH') {
        my @setting_candidates = grep {
            ref($hash->{HC_SETMAP}{$_}) eq 'HASH' && ($hash->{HC_SETMAP}{$_}{kind} // '') eq 'setting'
        } keys %{ $hash->{HC_SETMAP} };
        $a[1] = HomeConnectLocal_ResolveSetToken($hash, 'option', $a[1], \@setting_candidates);
    }

    # Generic direct XML setting:
    # set <device> SoundLevelSignal Medium
    # set <device> RinseAid R04
    # set <device> ExtraDry on
    if (ref($hash->{HC_SETMAP}) eq 'HASH'
        && ref($hash->{HC_SETMAP}{$a[1]}) eq 'HASH'
        && ($hash->{HC_SETMAP}{$a[1]}{kind} // '') eq 'setting'
        && $a[1] ne 'PowerState') {

        my $setting_name = $a[1];
        my $e = $hash->{HC_SETMAP}{$setting_name};

        return "Usage: set $n $setting_name <value>" if @a < 3;
        my $input = $a[2];

        my $access = $e->{access} // '';
        return "Setting '$setting_name' ist nicht schreibbar (access=$access)."
            if $access !~ /^(?:readWrite|writeOnly)$/;
        return "Setting '$setting_name' ist laut XML nicht verfuegbar."
            if defined($e->{available}) && "$e->{available}" eq 'false';

        my $uid = $e->{uid};
        return "Keine UID fuer Setting '$setting_name' gefunden."
            if !defined($uid) || $uid eq '';

        my ($value, $enum_type);
        $enum_type = $e->{enumerationType};
        if ((!defined($enum_type) || $enum_type eq '')
            && ref($hash->{Mapping}{EnumTypeByUID}) eq 'HASH') {
            $enum_type = $hash->{Mapping}{EnumTypeByUID}{$uid};
        }

        if (defined($enum_type) && $enum_type ne '') {
            my $enum_values =
                ref($hash->{Mapping}{EnumValues}) eq 'HASH'
                ? $hash->{Mapping}{EnumValues}{$enum_type} : undef;
            return "EnumValues fuer '$setting_name' ($enum_type) fehlen."
                if ref($enum_values) ne 'HASH';

            my @setting_value_candidates = values %$enum_values;
            $input = HomeConnectLocal_ResolveSetToken($hash, 'value', $input, \@setting_value_candidates);
            for my $numeric (keys %$enum_values) {
                my $name = $enum_values->{$numeric};
                if (defined($name) && lc("$name") eq lc($input)) {
                    $value = 0 + $numeric;
                    last;
                }
            }

            if (!defined($value)) {
                my @allowed = map { $enum_values->{$_} }
                    sort { $a <=> $b } grep { /^\d+$/ } keys %$enum_values;
                return "Ungueltiger Wert '$input' fuer '$setting_name'. Erlaubt: "
                    . join(", ", @allowed);
            }
        }
        elsif (($e->{refCID} // '') eq '01' && ($e->{refDID} // '') eq '00') {
            my @bool_candidates = qw(on off);
            $input = HomeConnectLocal_ResolveSetToken($hash, 'value', $input, \@bool_candidates);
            if ($input =~ /^(?:on|true|1)$/i) {
                $value = JSON::PP::true;
            } elsif ($input =~ /^(?:off|false|0)$/i) {
                $value = JSON::PP::false;
            } else {
                return "Ungueltiger Wert '$input' fuer '$setting_name'. Erlaubt: on, off";
            }
        }
        elsif ($input =~ /^-?(?:\d+(?:\.\d*)?|\.\d+)$/) {
            my $num = 0 + $input;
            return "Wert fuer '$setting_name' ist zu klein (min=$e->{min})."
                if defined($e->{min}) && $num < $e->{min};
            return "Wert fuer '$setting_name' ist zu gross (max=$e->{max})."
                if defined($e->{max}) && $num > $e->{max};

            if (defined($e->{stepSize}) && $e->{stepSize} > 0
                && defined($e->{min})) {
                my $steps = ($num - $e->{min}) / $e->{stepSize};
                my $nearest = int($steps + ($steps >= 0 ? 0.5 : -0.5));
                return "Ungueltige Schrittweite fuer '$setting_name' (stepSize=$e->{stepSize})."
                    if abs($steps - $nearest) > 1e-9;
            }
            $value = $num;
        }
        else {
            return "Setting '$setting_name' mit refCID="
                . ($e->{refCID} // '?') . " refDID=" . ($e->{refDID} // '?')
                . " wird noch nicht unterstuetzt.";
        }

        my $protocol_uid = hex($uid);

        Log3 $n, 5,
            "HomeConnectLocal ($n) - SETTING SEND: resource=/ro/values action=POST "
          . "setting='$setting_name' feature=" . ($e->{feature} // '')
          . " xmlUID=$uid protocolUID=$protocol_uid"
          . (defined($enum_type) && $enum_type ne '' ? " enumType=$enum_type" : "")
          . " input='$input'";

        my $sent = HomeConnectLocal_SendProtocol(
            $hash, "/ro/values", 1, "POST",
            { uid => 0 + $protocol_uid, value => $value }
        );

        return "Setting '$setting_name' konnte nicht gesendet werden. Bitte Verbindung/Log pruefen."
            if !$sent;

        return undef;
    }

    if ($a[1] eq "power") {
        return "Usage: set $n power on|off"
            if @a < 3 || $a[2] !~ /^(?:on|off)$/i;

        # Resolve PowerState from the XML-derived set map.
        my $power;
        if (ref($hash->{HC_SETMAP}) eq 'HASH') {
            for my $sn (keys %{ $hash->{HC_SETMAP} }) {
                my $e = $hash->{HC_SETMAP}{$sn};
                next if ref($e) ne 'HASH';
                my $feature = $e->{feature} // '';
                if ($feature eq 'BSH.Common.Setting.PowerState'
                    || $feature =~ /\.PowerState$/) {
                    $power = $e;
                    last;
                }
            }
        }

        return "PowerState wurde im XML-Mapping nicht gefunden."
            if !defined($power) || !defined($power->{uid});

        my $want = lc($a[2]);

        # HC_SETMAP stores the enumeration type, while the actual numeric
        # values live in Mapping->{EnumValues}{<enumerationType>}.
        my $enum_type = $power->{enumerationType};
        if (!defined($enum_type)
            && ref($hash->{Mapping}{EnumTypeByUID}) eq 'HASH') {
            $enum_type = $hash->{Mapping}{EnumTypeByUID}{$power->{uid}};
        }

        return "EnumerationType fuer PowerState wurde im XML-Mapping nicht gefunden."
            if !defined($enum_type) || $enum_type eq "";

        my $enum_values =
            ref($hash->{Mapping}{EnumValues}) eq 'HASH'
            ? $hash->{Mapping}{EnumValues}{$enum_type}
            : undef;

        return "EnumValues fuer PowerState ($enum_type) wurden im XML-Mapping nicht gefunden."
            if ref($enum_values) ne 'HASH';

        my $value;
        for my $numeric (keys %$enum_values) {
            my $name = $enum_values->{$numeric};
            next if !defined($name);
            if (lc("$name") eq $want) {
                $value = 0 + $numeric;
                last;
            }
        }

        return "PowerState '$want' konnte nicht aus XML EnumValues $enum_type ermittelt werden."
            if !defined($value);

        my $protocol_uid = hex($power->{uid});
        my $data = {
            uid   => 0 + $protocol_uid,
            value => 0 + $value
        };

        Log3 $n, 5,
            "HomeConnectLocal ($n) - POWER SEND: "
          . "resource=/ro/values action=POST "
          . "feature=$power->{feature} xmlUID=$power->{uid} "
          . "protocolUID=$protocol_uid enumType=$enum_type "
          . "state=$want value=$value";

        my $sent = HomeConnectLocal_SendProtocol(
            $hash,
            "/ro/values",
            1,
            "POST",
            $data
        );

        if (!$sent) {
            Log3 $n, 3,
                "HomeConnectLocal ($n) - POWER SEND fehlgeschlagen: '$want'";
            return "Power '$want' konnte nicht gesendet werden. Bitte Verbindung/Log pruefen.";
        }

        return undef;
    }

    if ($a[1] eq "start") {
        # Do not even send a start request unless the appliance explicitly
        # reports that remote starting is currently allowed.
        my $remote_start = ReadingsVal($n, "RemoteControlStartAllowed", "");
        if (lc($remote_start) ne "true") {
            Log3 $n, 5,
                "HomeConnectLocal ($n) - START BLOCKED: "
              . "RemoteControlStartAllowed='$remote_start'";
            return "Programmstart nicht moeglich: RemoteControlStartAllowed ist "
                 . ($remote_start eq "" ? "nicht verfuegbar" : "'$remote_start'")
                 . ".";
        }

        my $active = HomeConnectLocal_FindProgramRoot($hash, 'activeProgram');
        return "ActiveProgram wurde im XML-Mapping nicht gefunden."
            if !defined($active);

        # Prefer the value reported by the appliance.  The mapped parser
        # normally exposes BSH.Common.Root.SelectedProgram as SelectedProgram.
        my $selected_name = ReadingsVal($n, "SelectedProgram", "");
        $selected_name = ReadingsVal($n, "selectedProgramCandidate", "")
            if $selected_name eq "";

        return "Kein Programm ausgewaehlt. Bitte zuerst 'set $n program <Programm>' verwenden."
            if $selected_name eq "";

        my $p = HomeConnectLocal_FindProgram($hash, $selected_name);

        # Some mappings/readings may contain the fully qualified feature name.
        if (!defined($p) && ref($hash->{HC_PROGRAMS}) eq 'ARRAY') {
            for my $candidate (@{ $hash->{HC_PROGRAMS} }) {
                next if ref($candidate) ne 'HASH';
                if ((defined($candidate->{feature}) && $candidate->{feature} eq $selected_name)
                    || (defined($candidate->{uid}) && $candidate->{uid} eq $selected_name)) {
                    $p = $candidate;
                    last;
                }
            }
        }

        return "Ausgewaehltes Programm '$selected_name' konnte nicht der XML-Programmliste zugeordnet werden."
            if !defined($p);

        my $program_uid = hex($p->{uid});
        my $payload = {
            program => 0 + $program_uid
        };

        my @options;
        my %allowed = map { $_ => 1 } @{ $p->{optionUIDs} || [] };
        if (ref($hash->{HC_SELECTED_PROGRAM_OPTIONS}) eq 'HASH') {
            for my $ouid (sort keys %{ $hash->{HC_SELECTED_PROGRAM_OPTIONS} }) {
                next if !$allowed{$ouid};
                my $oe = $hash->{HC_SELECTED_PROGRAM_OPTIONS}{$ouid};
                next if ref($oe) ne 'HASH';

                push @options, {
                    uid   => 0 + hex($ouid),
                    value => $oe->{value}
                };
            }
        }
        $payload->{options} = \@options if @options;

        Log3 $n, 5,
            "HomeConnectLocal ($n) - START SEND: "
          . "resource=/ro/activeProgram action=POST "
          . "program='$p->{name}' xmlProgramUID=$p->{uid} "
          . "protocolValue=$program_uid data=" . encode_json($payload);

        my $sent = HomeConnectLocal_SendProtocol(
            $hash,
            "/ro/activeProgram",
            1,
            "POST",
            $payload
        );

        if (!$sent) {
            Log3 $n, 3,
                "HomeConnectLocal ($n) - START SEND fehlgeschlagen: '$p->{name}'";
            return "Programm '$p->{name}' konnte nicht gestartet werden. Bitte Verbindung/Log pruefen.";
        }

        return undef;
    }

    if ($a[1] eq "stop") {
        # AbortProgram is a normal RO command (XML UID 0200 = protocol UID 512).
        # hcpy sends this through /ro/values with value=true.
        my $abort_uid = "0200";
        if ($hash->{Mapping}
            && $hash->{Mapping}{UIDByFeature}
            && $hash->{Mapping}{UIDByFeature}{"BSH.Common.Command.AbortProgram"}) {
            $abort_uid =
                $hash->{Mapping}{UIDByFeature}{"BSH.Common.Command.AbortProgram"};
        }

        my $protocol_uid = hex($abort_uid);
        my $data = {
            uid   => $protocol_uid,
            value => JSON::PP::true
        };

        Log3 $n, 5,
            "HomeConnectLocal ($n) - STOP SEND: "
          . "resource=/ro/values action=POST "
          . "AbortProgram xmlUID=$abort_uid protocolUID=$protocol_uid "
          . "value=true";

        my $sent = HomeConnectLocal_SendProtocol(
            $hash,
            "/ro/values",
            1,
            "POST",
            $data
        );

        if (!$sent) {
            Log3 $n, 3,
                "HomeConnectLocal ($n) - STOP SEND fehlgeschlagen";
            return "Aktives Programm konnte nicht gestoppt werden. Bitte Verbindung/Log pruefen.";
        }

        return undef;
    }

    if ($a[1] =~ /^(?:pause|resume)$/) {
        my $cmd = $a[1];
        Log3 $n, 5, "HomeConnectLocal ($n) - COMMAND TEST: '$cmd'";
        return "Befehl '$cmd' erkannt, aber noch nicht gesendet.";
    }

    return "Unknown argument $a[1], choose one of " . HomeConnectLocal_SetList($hash);
}


##############################################
# JSON/FHEMWEB UTF-8 boundary (v32)
##############################################

sub HomeConnectLocal_JsonUnicode {
    my ($value) = @_;
    if (ref($value) eq 'HASH') {
        return { map { $_ => HomeConnectLocal_JsonUnicode($value->{$_}) } keys %$value };
    }
    if (ref($value) eq 'ARRAY') {
        return [ map { HomeConnectLocal_JsonUnicode($_) } @$value ];
    }
    return $value if ref($value) || !defined($value);

    # Translation strings are intentionally kept as UTF-8 byte strings for
    # normal FHEM readings/SetList. JSON::PP expects Perl character strings,
    # otherwise it UTF-8-encodes those bytes a second time (e.g. Bü -> BÃ¼).
    # Decode only valid UTF-8 byte strings at this JSON boundary.
    my $decoded = eval { decode('UTF-8', $value, FB_CROAK) };
    return defined($decoded) ? $decoded : $value;
}

##############################################
# Get
##############################################

sub HomeConnectLocal_Get {
    my (
        $hash,
        @a
    ) = @_;


    my $n =
        $hash->{NAME};


    return
        "Need an argument"
        if @a < 2;


    return
        $hash->{DeviceID}
        if $a[1] eq
           "deviceID";


    return
        ReadingsVal(
            $n,
            "state",
            "unknown"
        )
        if $a[1] eq
           "status";


    if ($a[1] eq "programConfig") {
        my $p = HomeConnectLocal_CurrentSelectedProgram($hash);
        my @programs = map { $_->{name} }
                       grep { ref($_) eq 'HASH' && defined($_->{name}) && $_->{name} ne '' }
                       @{ $hash->{HC_PROGRAMS} || [] };
        my @options;
        if (defined($p) && ref($p->{optionUIDs}) eq 'ARRAY') {
            my %seen;
            for my $ouid (@{ $p->{optionUIDs} }) {
                my $e = HomeConnectLocal_FindSetEntryByUID($hash, $ouid);
                next if ref($e) ne 'HASH' || ($e->{kind} // '') ne 'option';
                $e = HomeConnectLocal_ProgramOptionContextMeta(
                    $hash, $p, HomeConnectLocal_NormalizeHex($ouid), $e
                );
                my $sn = $e->{setName} // '';
                next if $sn eq '' || $seen{$sn}++;
                # v22: the preparation wizard is for actual programme parameters.
                # Scheduling/meta options stay available through normal FHEM sets.
                next if $sn eq 'FinishInRelative' || $sn eq 'Duration';

                my $acc = lc($e->{access} // '');
                # v33: WasherDryer exposes a dedicated live writable option
                # container (e.g. parent 161D), so keep the strict runtime rule
                # there. Dishwashers are different: their programme options are
                # sent as part of /ro/selectedProgram and many firmwares do not
                # expose those option UIDs as a separate writable live parent in
                # /ro/allDescriptionChanges. In that case the selected program's
                # <option refUID=...> relation is the authoritative capability
                # declaration. Do not hide those options from the popup merely
                # because runtimeLiveContext is absent.
                my $dtype = lc(AttrVal($n, 'deviceType', ''));
                my $is_dishwasher = ($dtype eq 'dishwasher') ? 1 : 0;
                if (!$is_dishwasher) {
                    next if !$e->{runtimeLiveContext};
                    next if $acc !~ /^(?:readwrite|writeonly)$/;
                    next if defined($e->{available}) && lc("$e->{available}") eq 'false';
                } else {
                    # An explicit live unavailable=false is still authoritative.
                    # Otherwise the program-specific XML option metadata decides.
                    next if defined($e->{available}) && lc("$e->{available}") eq 'false';
                }

                my %o = (name => $sn, uid => $e->{uid});
                my $enum_type = $e->{enumType} // $e->{enumerationType};
                if (defined($enum_type) && $enum_type ne '') {
                    my @vals = ($sn eq 'ProgramMode')
                        ? map { $_->[1] } HomeConnectLocal_ProgramModeMenuPairs($hash, $e)
                        : HomeConnectLocal_EnumMenuValues($hash, $e);
                    next if !@vals;
                    $o{type} = 'enum';
                    $o{values} = \@vals;
                }
                elsif (HomeConnectLocal_IsBooleanProgramOption($e)) {
                    $o{type} = 'bool';
                    $o{values} = ['off','on'];
                }
                elsif (defined($e->{min}) && defined($e->{max})) {
                    $o{type} = 'number';
                    $o{min} = 0 + $e->{min};
                    $o{max} = 0 + $e->{max};
                    $o{step} = defined($e->{stepSize}) ? 0 + $e->{stepSize} : 1;
                }
                else { next; }

                my $cur = ReadingsVal($n, 'option_' . $sn, '');
                $o{current} = $cur if defined($cur) && $cur ne '';
                push @options, \%o;
            }
        }
        my %program_config_order = (
            ProgramMode => 10,
            Temperature => 20,
            SpinSpeed => 30,
            DryingTarget => 40,
        );
        @options = sort {
            ($program_config_order{$a->{name}} // 100) <=> ($program_config_order{$b->{name}} // 100)
            || lc($a->{name}) cmp lc($b->{name})
        } @options;

        my %program_labels = map { $_ => HomeConnectLocal_DisplayText($hash, 'program', $_) } @programs;
        for my $o (@options) {
            next if ref($o) ne 'HASH';
            $o->{label} = HomeConnectLocal_DisplayText($hash, 'option', $o->{name});
            if (ref($o->{values}) eq 'ARRAY') {
                my %vl = map { $_ => HomeConnectLocal_DisplayText($hash, 'value', $_) } @{ $o->{values} };
                $o->{valueLabels} = \%vl;
            }
        }
        my $translation = AttrVal($n, 'translation', 'off');
        my $alias = AttrVal($n, 'alias', '');
        my $display_name = defined($alias) && $alias ne '' ? $alias : $n;
        my $cfg = {
            device => $n,
            displayName => $display_name,
            selectedProgram => defined($p) ? $p->{name} : '',
            programs => \@programs,
            programLabels => \%program_labels,
            translation => $translation,
            options => \@options,
            running => HomeConnectLocal_IsProgramRunning($hash) ? JSON::PP::true : JSON::PP::false,
            runtimeRevision => 0 + ($hash->{RuntimeMetaRevision} // 0)
        };
        return encode_json(HomeConnectLocal_JsonUnicode($cfg));
    }

    if (
        $a[1] eq "mapping"
    ) {

        return
            "not loaded"
            if !$hash->{MappingLoaded};


        return
              "prefix="
            . (
                $hash->{MappingPrefix}
                // ""
            )
            . " device="
            . (
                $hash->{MappingDeviceFile}
                // ""
            )
            . " feature="
            . (
                $hash->{MappingFeatureFile}
                // ""
            );
    }


    return
        "Unknown argument $a[1], choose one of "
        . "deviceID status mapping programConfig";
}


##############################################
# Display translation (v29: byte-safe UTF-8 translation helper)
##############################################

sub HomeConnectLocal_LoadTranslation {
    my ($hash) = @_;
    return 1 if defined(&HomeConnectLocal_TranslateDisplay);
    my $modpath = AttrVal('global', 'modpath', '.');
    my $file = $modpath . '/FHEM/HomeConnectLocal_Translation.pm';
    my $ok = eval { require $file; 1; };
    if (!$ok) {
        Log3 $hash->{NAME}, 3, "HomeConnectLocal ($hash->{NAME}) - Uebersetzungsdatei konnte nicht geladen werden: $file: $@" if $hash;
        return 0;
    }
    return 1;
}

sub HomeConnectLocal_DisplayText {
    my ($hash, $category, $value) = @_;
    return $value if !defined($value) || $value eq '';
    my $mode = AttrVal($hash->{NAME}, 'translation', 'off');
    return $value if !defined($mode) || lc($mode) eq 'off';
    return $value if !HomeConnectLocal_LoadTranslation($hash);
    my $dtype = lc(AttrVal($hash->{NAME}, 'deviceType', ''));
    return HomeConnectLocal_TranslateDisplay($mode, $dtype, $category, $value);
}

sub HomeConnectLocal_SetDisplayToken {
    my ($hash, $category, $value) = @_;
    return $value if !defined($value) || $value eq '';
    my $mode = AttrVal($hash->{NAME}, 'translation', 'off');
    return $value if !defined($mode) || lc($mode) eq 'off';
    return $value if !HomeConnectLocal_LoadTranslation($hash);
    my $dtype = lc(AttrVal($hash->{NAME}, 'deviceType', ''));
    return HomeConnectLocal_DisplayToken($mode, $dtype, $category, $value)
        if defined(&HomeConnectLocal_DisplayToken);
    return $value;
}

sub HomeConnectLocal_ResolveSetToken {
    my ($hash, $category, $input, $candidates) = @_;
    return $input if !defined($input);
    my $mode = AttrVal($hash->{NAME}, 'translation', 'off');
    return $input if !defined($mode) || lc($mode) eq 'off';
    return $input if !HomeConnectLocal_LoadTranslation($hash);
    my $dtype = lc(AttrVal($hash->{NAME}, 'deviceType', ''));
    return HomeConnectLocal_ResolveDisplayToken($mode, $dtype, $category, $input, $candidates)
        if defined(&HomeConnectLocal_ResolveDisplayToken);
    return $input;
}

##############################################
# FHEMWEB program configuration popup (v23)
##############################################

sub HomeConnectLocal_FwDetail {
    my ($FW_wname, $d, $room, $pageHash) = @_;
    return '' if $pageHash;
    my $hash = $defs{$d};
    return '' if !$hash;
    # v27: The program preparation popup is opt-in. This only controls the
    # FHEMWEB button; SetList, readings and protocol handling remain untouched.
    return '' if lc(AttrVal($d, 'programPopup', 'off') // 'off') ne 'on';
    my $safe = $d;
    $safe =~ s/&/&amp;/g; $safe =~ s/</&lt;/g; $safe =~ s/>/&gt;/g;
    $safe =~ s/"/&quot;/g; $safe =~ s/'/&#39;/g;
    return "<div class='makeTable wide homeconnectlocal-config-box'>"
         . "<span>Programmkonfiguration</span><div style='padding:8px 0'>"
         . "<button type='button' class='homeconnectlocal-config-open' data-device='$safe'>"
         . "Programm vorbereiten</button></div></div>";
}

##############################################
# Reading filter helpers
##############################################

my %HomeConnectLocal_RawReading = map { $_ => 1 } qw(
    authentication ci_info descriptionChanges iz_info mandatoryValues
    ni_info registeredDevices services values
);

sub HomeConnectLocal_RawReadingHidden {
    my ($hash, $reading) = @_;
    return 0 if !$hash || !defined($reading);
    return 0 if !$HomeConnectLocal_RawReading{$reading};
    return AttrVal($hash->{NAME}, 'showRawReadings', 0) ? 0 : 1;
}

sub HomeConnectLocal_ApplyRawReadingVisibility {
    my ($hash) = @_;
    return if !$hash;
    return if AttrVal($hash->{NAME}, 'showRawReadings', 0);
    for my $reading (keys %HomeConnectLocal_RawReading) {
        readingsDelete($hash, $reading) if exists $hash->{READINGS}{$reading};
    }
    return;
}

sub HomeConnectLocal_ReadingExcluded {
    my ($hash, $reading, $value) = @_;

    return 0 if !$hash || !defined($reading) || $reading eq "state";

    my $list = defined($value)
        ? $value
        : AttrVal($hash->{NAME}, "excludeReadings", "");

    return 0 if !defined($list) || $list eq "";

    for my $pattern (grep { length($_) } split(/[\s,;]+/, $list)) {
        my $regex = quotemeta($pattern);
        $regex =~ s/\\\*/.*/g;
        $regex =~ s/\\\?/./g;

        return 1 if $reading =~ /^$regex$/;
    }

    return 0;
}


sub HomeConnectLocal_TranslatedReading {
    my ($hash, $reading, $value) = @_;
    return if !$hash || !defined($reading) || !defined($value);
    return if $reading =~ /_(?:DE|EN)$/;

    my $mode = uc(AttrVal($hash->{NAME}, 'translation', 'off') // 'off');
    return if $mode ne 'DE' && $mode ne 'EN';
    return if !HomeConnectLocal_LoadTranslation($hash);
    return if !defined(&HomeConnectLocal_TranslateReadingValue);

    my $dtype = lc(AttrVal($hash->{NAME}, 'deviceType', ''));
    my $translated = HomeConnectLocal_TranslateReadingValue($mode, $dtype, $reading, $value);
    return if !defined($translated) || $translated eq '' || "$translated" eq "$value";

    return ($reading . '_' . $mode, $translated);
}

sub HomeConnectLocal_ReadingsSingleUpdate {
    my ($hash, $reading, $value, $trigger) = @_;

    return if HomeConnectLocal_RawReadingHidden($hash, $reading);
    return if HomeConnectLocal_ReadingExcluded($hash, $reading);

    my $ret = readingsSingleUpdate($hash, $reading, $value, $trigger);
    my ($tr, $tv) = HomeConnectLocal_TranslatedReading($hash, $reading, $value);
    if (defined($tr) && !HomeConnectLocal_ReadingExcluded($hash, $tr)) {
        readingsSingleUpdate($hash, $tr, $tv, $trigger);
    }
    return $ret;
}

sub HomeConnectLocal_ReadingsBulkUpdate {
    my ($hash, $reading, $value, @rest) = @_;

    return if HomeConnectLocal_RawReadingHidden($hash, $reading);
    return if HomeConnectLocal_ReadingExcluded($hash, $reading);

    my $ret = readingsBulkUpdate($hash, $reading, $value, @rest);
    my ($tr, $tv) = HomeConnectLocal_TranslatedReading($hash, $reading, $value);
    if (defined($tr) && !HomeConnectLocal_ReadingExcluded($hash, $tr)) {
        readingsBulkUpdate($hash, $tr, $tv, @rest);
    }
    return $ret;
}

sub HomeConnectLocal_RebuildTranslatedReadings {
    my ($hash) = @_;
    return if !$hash;

    # Remove generated language readings first, so switching DE/EN/off is clean.
    for my $r (keys %{ $hash->{READINGS} // {} }) {
        readingsDelete($hash, $r) if $r =~ /_(?:DE|EN)$/;
    }

    my $mode = uc(AttrVal($hash->{NAME}, 'translation', 'off') // 'off');
    return if $mode ne 'DE' && $mode ne 'EN';

    for my $r (sort keys %{ $hash->{READINGS} // {} }) {
        next if $r =~ /_(?:DE|EN)$/;
        next if HomeConnectLocal_RawReadingHidden($hash, $r);
        my $v = ReadingsVal($hash->{NAME}, $r, undef);
        next if !defined($v);
        my ($tr, $tv) = HomeConnectLocal_TranslatedReading($hash, $r, $v);
        next if !defined($tr) || HomeConnectLocal_ReadingExcluded($hash, $tr);
        readingsSingleUpdate($hash, $tr, $tv, 0);
    }
}


sub HomeConnectLocal_ApplyExcludedReadings {
    my ($hash, $value) = @_;

    return if !$hash || !defined($value) || $value eq "";

    for my $reading (keys %{ $hash->{READINGS} // {} }) {
        next if $reading eq "state";
        next if !HomeConnectLocal_ReadingExcluded($hash, $reading, $value);

        readingsDelete($hash, $reading);
    }

    return;
}


sub HomeConnectLocal_TranslationAttrTimer {
    my ($hash) = @_;
    HomeConnectLocal_RebuildTranslatedReadings($hash);
    return;
}

##############################################
# Attr
##############################################

sub HomeConnectLocal_Attr {
    my (
        $cmd,
        $name,
        $attr,
        $value
    ) = @_;


    my $hash =
        $defs{$name};


    return
        if !$hash;


    if ($attr eq "showRawReadings") {
        # Default is 0. Switching back to 0 removes already existing raw JSON
        # readings immediately. With 1 they are populated again by subsequent
        # protocol messages (normally after reconnect).
        if ($cmd eq "set" && !($value // 0)) {
            InternalTimer(gettimeofday() + 0.1, 'HomeConnectLocal_ApplyRawReadingVisibility', $hash, 0);
        }
        return undef;
    }

    if ($attr eq "excludeReadings") {
        if ($cmd eq "set") {
            HomeConnectLocal_ApplyExcludedReadings(
                $hash,
                $value // ""
            );
        }

        return undef;
    }

    if ($attr eq "excludeSets") {
        # SetList is generated dynamically on every request; no rebuild is
        # required. Wildcards * and ? are supported like excludeReadings.
        return undef;
    }

    if ($attr eq "translation") {
        # Translation never changes protocol readings. It only adds/removes
        # generated *_DE / *_EN companion readings. Rebuild after AttrVal
        # has been committed by FHEM; normal runtime updates keep them current.
        InternalTimer(gettimeofday() + 0.1, 'HomeConnectLocal_TranslationAttrTimer', $hash, 0);
        return undef;
    }

    if ($attr eq "programPopup") {
        # FHEMWEB evaluates FW_detailFn on the next page render. No protocol
        # or runtime map rebuild is needed for this display-only attribute.
        return undef;
    }


    if (
        $attr =~
        /^(?:encryptionKey|connectionType|iv|disable|mappingDir|mappingPrefix|deviceType)$/
    ) {

        RemoveInternalTimer(
            $hash
        );


        if (
            $attr eq "disable" &&
            defined($value) &&
            $value
        ) {

            HomeConnectLocal_Undefine(
                $hash
            );


            HomeConnectLocal_ReadingsSingleUpdate(
                $hash,
                "state",
                "disabled",
                1
            );


            return undef;
        }


        if (
            $attr =~
            /^(?:mappingDir|mappingPrefix|deviceType)$/
        ) {

            HomeConnectLocal_LoadMapping(
                $hash
            );


            return undef;
        }


        InternalTimer(
            time() + 1,
            "HomeConnectLocal_Connect",
            $hash,
            0
        );
    }


    return undef;
}



########################################################################################
# FHEM commandref documentation
########################################################################################

=pod
=item device
=item summary local communication with Home Connect appliances
=item summary_DE Lokale Kommunikation mit Home-Connect-Hausger&auml;ten

=begin html

<a id="HomeConnectLocal"></a>
<h3>HomeConnectLocal</h3>
<ul>
  <p>FHEM module for local communication with compatible Home Connect appliances.
  The module communicates directly with the appliance in the local network and
  dynamically loads device capabilities from Home Connect XML mapping files.</p>

  <a id="HomeConnectLocal-define"></a>
  <h4>Define</h4>
  <p><code>define &lt;name&gt; HomeConnectLocal &lt;IP address&gt;</code></p>
  <p>Example: <code>define Dishwasher_Local HomeConnectLocal 192.168.1.55</code></p>
  <p>The appliance pairing key is configured with the <code>encryptionKey</code>
  attribute. Mapping files are loaded from <code>mappingDir</code>.</p>

  <a id="HomeConnectLocal-set"></a>
  <h4>Set</h4>
  <ul>
    <li><code>set &lt;name&gt; connect</code> &ndash; establish/re-establish the local connection.</li>
    <li><code>set &lt;name&gt; disconnect</code> &ndash; close the local connection.</li>
    <li><code>set &lt;name&gt; reloadMapping</code> &ndash; reload XML mapping files.</li>
    <li><code>set &lt;name&gt; program &lt;program&gt;</code> &ndash; select a program. Available programs are generated dynamically.</li>
    <li><code>set &lt;name&gt; start</code> &ndash; start the selected program when remote start is permitted by the appliance.</li>
    <li><code>set &lt;name&gt; stop</code> &ndash; stop the active program.</li>
    <li><code>set &lt;name&gt; pause|resume</code> &ndash; pause/resume where supported.</li>
    <li><code>set &lt;name&gt; power on|off</code> &ndash; change appliance power state where supported.</li>
    <li>Program options and writable settings are added dynamically from XML and current runtime metadata.</li>
  </ul>

  <a id="HomeConnectLocal-get"></a>
  <h4>Get</h4>
  <ul>
    <li><code>get &lt;name&gt; status</code> &ndash; return the current FHEM state.</li>
    <li><code>get &lt;name&gt; deviceID</code> &ndash; return the local application DeviceID.</li>
    <li><code>get &lt;name&gt; mapping</code> &ndash; show the currently loaded mapping files.</li>
    <li><code>get &lt;name&gt; programConfig</code> &ndash; JSON configuration used by the program preparation popup.</li>
  </ul>

  <a id="HomeConnectLocal-attr"></a>
  <h4>Attributes</h4>
  <ul>
    <li><code>disable 0|1</code> &ndash; disable/enable communication.</li>
    <li><code>encryptionKey &lt;key&gt;</code> &ndash; appliance pairing/encryption key. Treat as confidential.</li>
    <li><code>connectionType TLS|AES</code> &ndash; local protocol connection type.</li>
    <li><code>iv &lt;value&gt;</code> &ndash; initialization-vector configuration where required by the selected connection type.</li>
    <li><code>deviceType dishwasher|hob|washer|washerdryer</code> &ndash; appliance class used for mapping selection and display logic.</li>
    <li><code>mappingDir &lt;directory&gt;</code> &ndash; directory containing XML mapping files. Default: <code>/opt/fhem/FHEM/FHEM_HomeConnectLocal</code>.</li>
    <li><code>mappingPrefix &lt;prefix&gt;</code> &ndash; explicitly select a mapping file pair by prefix.</li>
    <li><code>excludeReadings &lt;patterns&gt;</code> &ndash; hide/delete unwanted readings. Wildcards <code>*</code> and <code>?</code> are supported.</li>
    <li><code>showRawReadings 0|1</code> &ndash; show raw protocol JSON readings. Default is 0; enable only for diagnostics.</li>
    <li><code>excludeSets &lt;patterns&gt;</code> &ndash; hide SET commands from the generated FHEMWEB SetList. Wildcards are supported.</li>
    <li><code>translation off|DE|EN</code> &ndash; optional translated display/readings without changing protocol values.</li>
    <li><code>programPopup on|off</code> &ndash; enable the FHEMWEB program preparation popup.</li>
  </ul>

  <h4>Mapping files</h4>
  <p>Each appliance uses a matching <code>*_DeviceDescription.xml</code> and
  <code>*_FeatureMapping.xml</code> pair. Programs, options, settings, enums and
  feature names are derived dynamically from these files and refined by the
  live runtime description reported by the appliance.</p>

  <h4>Security</h4>
  <p>Cryptographic session material is stored privately by the module and is not
  exposed as normal FHEM Internals. Raw protocol readings are disabled by
  default because they may contain serial numbers, network configuration,
  registered-device information or other diagnostic data. The
  <code>encryptionKey</code> attribute itself remains sensitive FHEM configuration.</p>

  <h4>Logging</h4>
  <p>Verbose level 2 contains important lifecycle events, level 3 is reserved for
  errors, and level 5 contains detailed diagnostics and protocol debugging.</p>

  <h4>Standard attributes</h4>
  <p><a href="#alias">alias</a>, <a href="#comment">comment</a>,
  <a href="#event-on-update-reading">event-on-update-reading</a>,
  <a href="#event-on-change-reading">event-on-change-reading</a>,
  <a href="#room">room</a>, <a href="#verbose">verbose</a>,
  <a href="#webCmd">webCmd</a> and other standard reading attributes.</p>
</ul>

=end html

=begin html_DE

<a id="HomeConnectLocal"></a>
<h3>HomeConnectLocal</h3>
<ul>
  <p>FHEM-Modul zur lokalen Kommunikation mit kompatiblen Home-Connect-Hausger&auml;ten.
  Die Kommunikation erfolgt direkt im lokalen Netzwerk. Ger&auml;tefunktionen,
  Programme, Optionen und Einstellungen werden dynamisch aus den Home-Connect-XML-Mappingdateien ermittelt.</p>

  <a id="HomeConnectLocal-define"></a>
  <h4>Define</h4>
  <p><code>define &lt;name&gt; HomeConnectLocal &lt;IP-Adresse&gt;</code></p>
  <p>Beispiel: <code>define Spuelmaschine_Lokal HomeConnectLocal 192.168.1.55</code></p>
  <p>Der Pairing-/Verschl&uuml;sselungsschl&uuml;ssel des Hausger&auml;ts wird &uuml;ber das
  Attribut <code>encryptionKey</code> hinterlegt. Die Mappingdateien werden aus
  <code>mappingDir</code> geladen.</p>

  <a id="HomeConnectLocal-set"></a>
  <h4>Set</h4>
  <ul>
    <li><code>set &lt;name&gt; connect</code> &ndash; lokale Verbindung herstellen bzw. neu aufbauen.</li>
    <li><code>set &lt;name&gt; disconnect</code> &ndash; lokale Verbindung trennen.</li>
    <li><code>set &lt;name&gt; reloadMapping</code> &ndash; XML-Mappingdateien neu einlesen.</li>
    <li><code>set &lt;name&gt; program &lt;Programm&gt;</code> &ndash; Programm ausw&auml;hlen. Die Programmliste wird dynamisch erzeugt.</li>
    <li><code>set &lt;name&gt; start</code> &ndash; ausgew&auml;hltes Programm starten, sofern das Hausger&auml;t den Fernstart erlaubt.</li>
    <li><code>set &lt;name&gt; stop</code> &ndash; aktives Programm stoppen.</li>
    <li><code>set &lt;name&gt; pause|resume</code> &ndash; Programm pausieren/fortsetzen, sofern unterst&uuml;tzt.</li>
    <li><code>set &lt;name&gt; power on|off</code> &ndash; Ger&auml;tezustand &auml;ndern, sofern unterst&uuml;tzt.</li>
    <li>Programmspezifische Optionen und schreibbare Einstellungen werden dynamisch aus XML und Runtime-Metadaten als weitere SET-Befehle erg&auml;nzt.</li>
  </ul>

  <a id="HomeConnectLocal-get"></a>
  <h4>Get</h4>
  <ul>
    <li><code>get &lt;name&gt; status</code> &ndash; aktuellen FHEM-Status ausgeben.</li>
    <li><code>get &lt;name&gt; deviceID</code> &ndash; lokale Application-DeviceID ausgeben.</li>
    <li><code>get &lt;name&gt; mapping</code> &ndash; aktuell verwendete Mappingdateien anzeigen.</li>
    <li><code>get &lt;name&gt; programConfig</code> &ndash; JSON-Konfiguration f&uuml;r den Dialog &bdquo;Programm vorbereiten&ldquo; ausgeben.</li>
  </ul>

  <a id="HomeConnectLocal-attr"></a>
  <h4>Attribute</h4>
  <ul>
    <li><code>disable 0|1</code> &ndash; Kommunikation deaktivieren/aktivieren.</li>
    <li><code>encryptionKey &lt;Schl&uuml;ssel&gt;</code> &ndash; Pairing-/Verschl&uuml;sselungsschl&uuml;ssel des Hausger&auml;ts. Vertraulich behandeln.</li>
    <li><code>connectionType TLS|AES</code> &ndash; verwendete lokale Protokollverbindung.</li>
    <li><code>iv &lt;Wert&gt;</code> &ndash; Initialisierungsvektor, sofern f&uuml;r die gew&auml;hlte Verbindungsart erforderlich.</li>
    <li><code>deviceType dishwasher|hob|washer|washerdryer</code> &ndash; Ger&auml;teklasse f&uuml;r Mappingauswahl und Darstellungslogik.</li>
    <li><code>mappingDir &lt;Verzeichnis&gt;</code> &ndash; Verzeichnis der XML-Mappingdateien. Standard: <code>/opt/fhem/FHEM/FHEM_HomeConnectLocal</code>.</li>
    <li><code>mappingPrefix &lt;Pr&auml;fix&gt;</code> &ndash; ein bestimmtes Mapping-Dateipaar anhand seines Pr&auml;fixes ausw&auml;hlen.</li>
    <li><code>excludeReadings &lt;Muster&gt;</code> &ndash; nicht ben&ouml;tigte Readings ausblenden/l&ouml;schen. Wildcards <code>*</code> und <code>?</code> werden unterst&uuml;tzt.</li>
    <li><code>showRawReadings 0|1</code> &ndash; rohe Protokoll-JSON-Readings anzeigen. Standard ist 0; nur zur Diagnose aktivieren.</li>
    <li><code>excludeSets &lt;Muster&gt;</code> &ndash; SET-Befehle aus der dynamischen FHEMWEB-SetList ausblenden. Wildcards werden unterst&uuml;tzt.</li>
    <li><code>translation off|DE|EN</code> &ndash; optionale Anzeige/&Uuml;bersetzung, ohne die internen Protokollwerte zu ver&auml;ndern.</li>
    <li><code>programPopup on|off</code> &ndash; Dialog &bdquo;Programm vorbereiten&ldquo; in FHEMWEB aktivieren.</li>
  </ul>

  <h4>Mappingdateien</h4>
  <p>F&uuml;r jedes Hausger&auml;t wird ein zusammengeh&ouml;rendes Paar aus
  <code>*_DeviceDescription.xml</code> und <code>*_FeatureMapping.xml</code> verwendet.
  Programme, Optionen, Einstellungen, Enums und Bezeichnungen werden daraus
  dynamisch erzeugt und mit den aktuellen Runtime-Informationen des Hausger&auml;ts abgeglichen.</p>

  <h4>Sicherheit</h4>
  <p>Kryptografisches Sitzungsmaterial wird modul-intern gespeichert und nicht als
  normale FHEM-Internals angezeigt. Rohe Protokoll-Readings sind standardm&auml;&szlig;ig
  deaktiviert, da sie unter anderem Seriennummern, Netzwerkinformationen,
  registrierte Ger&auml;te oder andere Diagnosedaten enthalten k&ouml;nnen. Das Attribut
  <code>encryptionKey</code> bleibt selbstverst&auml;ndlich ein vertraulicher Bestandteil
  der FHEM-Konfiguration.</p>

  <h4>Logging</h4>
  <p>Verbose 2 enth&auml;lt wichtige Verbindungs- und Lebenszyklusmeldungen,
  Verbose 3 ausschlie&szlig;lich Fehler und Verbose 5 die ausf&uuml;hrliche Diagnose
  einschlie&szlig;lich Protokollinformationen.</p>

  <h4>Standardattribute</h4>
  <p><a href="#alias">alias</a>, <a href="#comment">comment</a>,
  <a href="#event-on-update-reading">event-on-update-reading</a>,
  <a href="#event-on-change-reading">event-on-change-reading</a>,
  <a href="#room">room</a>, <a href="#verbose">verbose</a>,
  <a href="#webCmd">webCmd</a> sowie die &uuml;blichen Reading-Attribute.</p>
</ul>

=end html_DE

=cut

1;
