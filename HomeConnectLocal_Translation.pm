# $Id$
package main;
use strict;
use warnings;

# HomeConnectLocal display translations.
# IMPORTANT: This file changes display text only. Protocol/set values stay original.
# Formatting: common translation tables use one entry per line for easier maintenance.

my %HCL_DE_COMMON_OPTION = (
    ProgramMode=>'Programmodus',
    Temperature=>'Temperatur',
    SpinSpeed=>'Schleuderdrehzahl',
    DryingTarget=>'Trockenziel',
    IntensivePlus=>'Intensiv Plus',
    LessIroning=>'Bügelleicht',
    LowTemperatureHygiene=>'Hygiene niedrige Temperatur',
    MultipleSoak=>'Mehrfach Einweichen',
    Prewash=>'Vorwäsche',
    RinseHold=>'Spülstopp',
    RinsePlus=>'Extra Spülen',
    SilentMode=>'Leise',
    SpeedPerfect=>'SpeedPerfect',
    Stains=>'Flecken',
    WaterPlus=>'Wasser Plus',
    WrinkleGuardBoost=>'Knitterschutz',
    ExtraDry=>'Extra Trocknen',
    HygienePlus=>'Hygiene Plus',
    IntensivZone=>'Intensivzone',
    SilenceOnDemand=>'Leise auf Abruf',
    VarioSpeedPlus=>'varioSpeed Plus',
    CookingSensorLevel=>'Kochsensor-Stufe',
    FryingSensorLevel=>'Bratsensor-Stufe',
    JoinZone=>'Zonen verbinden',
    PowerLevel=>'Leistungsstufe',
    PowerMoveModeValueFront=>'PowerMove vorne',
    PowerMoveModeValueMiddle=>'PowerMove Mitte',
    PowerMoveModeValueRear=>'PowerMove hinten',
    ZoneSelector=>'Zonenauswahl',
    AllowBackendConnection=>'Backend-Verbindung erlauben',
    BrandLogo=>'Markenlogo',
    DryingAssistantAllPrograms=>'Trocknungsassistent alle Programme',
    EcoAsDefault=>'Eco als Standard',
    EcoPrognosis=>'Eco-Prognose',
    HotWater=>'Warmwasser',
    InteriorLight=>'Innenbeleuchtung',
    InteriorLightMode=>'Innenbeleuchtungsmodus',
    Language=>'Sprache',
    RemoteControlLevel=>'Fernsteuerungsstufe',
    RinseAid=>'Klarspüler',
    SensitivityTurbidity=>'Trübungssensor-Empfindlichkeit',
    SilenceOnDemandDefaultTime=>'Leise-auf-Abruf Standarddauer',
    SoundLevelKey=>'Tastenton-Lautstärke',
    SoundLevelSignal=>'Signallautstärke',
    StartInRelative=>'Startzeit relativ',
    SynchronizeWithTimeServer=>'Mit Zeitserver synchronisieren',
    TimeFormat=>'Zeitformat',
    TimeLight=>'Zeitbeleuchtung',
    WaterHardness=>'Wasserhärte',
    'LearningDishwasher.Feedback.Cleaning'=>'Intelligent Feedback Reinigung',
    'LearningDishwasher.Feedback.Drying'=>'Intelligent Feedback Trocknung',
    'LearningDishwasher.Feedback.Duration'=>'Intelligent Feedback Dauer',
    'LearningDishwasher.InitialPreference.Cleaning'=>'Intelligent Startpräferenz Reinigung',
    'LearningDishwasher.InitialPreference.Drying'=>'Intelligent Startpräferenz Trocknung',
    'LearningDishwasher.InitialPreference.Duration'=>'Intelligent Startpräferenz Dauer',
    'SmartEnergyService.AutoSmartStartEnabled'=>'Smart Energy Auto-Start',
    'SmartEnergyService.SmartStartEnabled'=>'Smart Energy Start',
    'Time.DisplayMode'=>'Zeitanzeigemodus',
);

my %HCL_DE_COMMON_VALUE = (
    On=>'An',
    Off=>'Aus',
    on=>'An',
    off=>'Aus',
    Washing=>'Waschen',
    Drying=>'Trocknen',
    WashingAndDrying=>'Waschen und Trocknen',
    IronDry=>'Bügeltrocken',
    CupboardDry=>'Schranktrocken',
    CupboardDryPlus=>'Schranktrocken Plus',
    Cold=>'Kalt',
    Auto=>'Automatisch',
    KeepWarm=>'Warmhalten',
);

my %HCL_DE_PROGRAM = (
    washerdryer => {
        Cotton=>'Baumwolle', DelicatesSilk=>'Fein/Seide', DrumCare=>'Trommelreinigung & trocknen',
        HHSynthetics=>'Pflegeleicht', WD45=>'Extra Kurz 15 / Wash & Dry 45', FastHygiene=>'Fast Hygiene',
        Eco4060=>'Eco 40-60', LaundryWarming=>'Wäsche erwärmen', HHMix=>'Schnell/Mix',
        DrumDry=>'Feuchtigkeit entfernen', MyTimeDry=>'My Dry Time', Refresh=>'Auffrischen', Rinse=>'Spülen',
        Sensitive=>'Hygiene Plus', ShirtsBlouses=>'Blusen und Hemden', SpinDrain=>'Schleudern/Abpumpen',
        SportFitness=>'Sportswear', Wool=>'Wolle', PlushToy=>'Kuscheltiere',
    },
    washer => {
        Cotton=>'Baumwolle', Eco4060=>'Eco 40-60', EasyCare=>'Pflegeleicht', Mix=>'Schnell/Mix',
        DelicatesSilk=>'Fein/Seide', Wool=>'Wolle', SportFitness=>'Sportswear', SpinDrain=>'Schleudern/Abpumpen',
    },
    dishwasher => {
        Auto2=>'Auto 45–65 °C', Eco50=>'Eco 50 °C', Glas40=>'Glas 40 °C', Intensiv70=>'Intensiv 70 °C',
        Kurz60=>'Speed 60 °C', Quick45=>'Speed 45 °C', PreRinse=>'Vorspülen', MachineCare=>'Maschinenpflege',
        NightWash=>'Leise', MixedLoad=>'Schnell/Mix', 'Favorite.001'=>'Favorit', LearningDishwasher=>'Intelligent',
    },
    hob => {
        PowerLevelMode=>'Leistungsstufe', FryingSensorMode=>'Bratsensor', PowerMoveMode=>'PowerMove',
        CookingSensor=>'Kochsensor',
    },
);

my %HCL_DE_OPTION = (
    washerdryer => {}, washer => {},
    dishwasher => {
        ExtraDry=>'Extra Trocknen', HygienePlus=>'Hygiene Plus', IntensivZone=>'Intensivzone',
        SilenceOnDemand=>'Leise auf Abruf', VarioSpeedPlus=>'varioSpeed Plus',
        CleaningLevel=>'Reinigungsstufe', DryingLevel=>'Trocknungsstufe', DurationLevel=>'Dauerstufe',
    },
    hob => {
        CookingSensorLevel=>'Kochsensor-Stufe', FryingSensorLevel=>'Bratsensor-Stufe', JoinZone=>'Zonen verbinden',
        PowerLevel=>'Leistungsstufe', PowerMoveModeValueFront=>'PowerMove vorne',
        PowerMoveModeValueMiddle=>'PowerMove Mitte', PowerMoveModeValueRear=>'PowerMove hinten', ZoneSelector=>'Zonenauswahl',
    },
);

my %HCL_DE_VALUE = (
    washerdryer => {}, washer => {}, dishwasher => {}, hob => {},
);

sub HomeConnectLocal_PrettyEnglish {
    my ($value) = @_;
    return '' if !defined $value;
    my $s = "$value";
    return 'On'  if lc($s) eq 'on';
    return 'Off' if lc($s) eq 'off';
    return $s if $s =~ /^(?:GC|RPM)\d+$/ || $s =~ /^Eco\d+$/;
    $s =~ s/([a-z0-9])([A-Z])/$1 $2/g;
    $s =~ s/([A-Z]+)([A-Z][a-z])/$1 $2/g;
    return $s;
}

sub HomeConnectLocal_TranslateDisplay {
    my ($language, $device_type, $category, $value) = @_;
    return $value if !defined($value) || $value eq '';
    $language = uc($language // '');
    $device_type = lc($device_type // '');
    $category = lc($category // '');

    # Friendly units are display-only and valid for DE/EN.
    return "$1 °C" if $value =~ /^GC(\d+)$/;
    return "$1 U\/min" if $language eq 'DE' && $value =~ /^RPM(\d+)$/;
    return "$1 rpm" if $language eq 'EN' && $value =~ /^RPM(\d+)$/;

    if ($language eq 'DE') {
        if ($category eq 'program') {
            return $HCL_DE_PROGRAM{$device_type}{$value}
                if exists($HCL_DE_PROGRAM{$device_type}) && exists($HCL_DE_PROGRAM{$device_type}{$value});
            # Some installations use a broader deviceType (for example
            # 'washer' for a WasherDryer). Program names themselves are
            # unambiguous in our dictionaries, so use the other device maps
            # as a display-only fallback.
            for my $dt (qw(washerdryer washer dishwasher hob)) {
                next if $dt eq $device_type;
                return $HCL_DE_PROGRAM{$dt}{$value}
                    if exists($HCL_DE_PROGRAM{$dt}) && exists($HCL_DE_PROGRAM{$dt}{$value});
            }
        } elsif ($category eq 'option') {
            return $HCL_DE_OPTION{$device_type}{$value}
                if exists($HCL_DE_OPTION{$device_type}) && exists($HCL_DE_OPTION{$device_type}{$value});
            return $HCL_DE_COMMON_OPTION{$value} if exists $HCL_DE_COMMON_OPTION{$value};
        } elsif ($category eq 'value') {
            return $HCL_DE_VALUE{$device_type}{$value}
                if exists($HCL_DE_VALUE{$device_type}) && exists($HCL_DE_VALUE{$device_type}{$value});
            return $HCL_DE_COMMON_VALUE{$value} if exists $HCL_DE_COMMON_VALUE{$value};
        }
    }
    return HomeConnectLocal_PrettyEnglish($value);
}


sub HomeConnectLocal_DisplayToken {
    my ($language, $device_type, $category, $value) = @_;
    my $s = HomeConnectLocal_TranslateDisplay($language, $device_type, $category, $value);
    return $value if !defined($s) || $s eq '';
    # FHEM SetList uses spaces as separators. Keep the translated text
    # readable while making it a single safe token.
    if (uc($language // '') eq 'DE') {
        my %compact = (
            'Trommelreinigung & trocknen' => 'Trommelreinigung&Trocknen',
            'Extra Kurz 15 / Wash & Dry 45' => 'ExtraKurz15/Wash&Dry45',
            'Fast Hygiene' => 'FastHygiene',
            'Eco 40-60' => 'Eco40-60',
            'Wäsche erwärmen' => 'Wäsche_erwärmen',
            'Feuchtigkeit entfernen' => 'Feuchtigkeit_entfernen',
            'My Dry Time' => 'MyDryTime',
            'Hygiene Plus' => 'Hygiene_Plus',
            'Blusen und Hemden' => 'Blusen_und_Hemden',
        );
        $s = $compact{$s} if exists $compact{$s};
    }
    $s =~ s/\s+/_/g;
    $s =~ s/,/_/g;
    return $s;
}

sub HomeConnectLocal_ResolveDisplayToken {
    my ($language, $device_type, $category, $input, $candidates) = @_;
    return $input if !defined($input) || ref($candidates) ne 'ARRAY';
    my $needle = lc($input);
    for my $raw (@$candidates) {
        next if !defined($raw);
        my $disp = HomeConnectLocal_DisplayToken($language, $device_type, $category, $raw);
        return $raw if defined($disp) && lc($disp) eq $needle;
        return $raw if lc($raw) eq $needle;
    }
    return $input;
}


my %HCL_DE_READING_VALUE = (
    RemoteControlStartAllowed => { true=>'zugelassen', false=>'nicht zugelassen', 1=>'zugelassen', 0=>'nicht zugelassen' },
    RemoteControlActive       => { true=>'aktiv', false=>'inaktiv', 1=>'aktiv', 0=>'inaktiv' },
    LocalControlActive        => { true=>'aktiv', false=>'inaktiv', 1=>'aktiv', 0=>'inaktiv' },
    DoorState                 => { Open=>'offen', Closed=>'geschlossen', Locked=>'verriegelt' },
    OperationState            => { Ready=>'Bereit', Inactive=>'Ruhezustand', Run=>'Läuft', Finished=>'Fertig', Pause=>'Pause', Aborting=>'Abbruch', Error=>'Fehlerzustand' },
    PowerState                => { On=>'An', Off=>'Aus', PowerOn=>'An', PowerOff=>'Aus', PowerStandby=>'Standby' },
    ChildLock                 => { On=>'An', Off=>'Aus', true=>'An', false=>'Aus', 1=>'An', 0=>'Aus' },
);

my %HCL_EN_READING_VALUE = (
    RemoteControlStartAllowed => { true=>'allowed', false=>'not allowed', 1=>'allowed', 0=>'not allowed' },
    RemoteControlActive       => { true=>'active', false=>'inactive', 1=>'active', 0=>'inactive' },
    LocalControlActive        => { true=>'active', false=>'inactive', 1=>'active', 0=>'inactive' },
);

sub HomeConnectLocal_TranslateReadingValue {
    my ($language, $device_type, $reading, $value) = @_;
    return undef if !defined($reading) || !defined($value) || $value eq '';
    $language = uc($language // '');
    $device_type = lc($device_type // '');

    my $specific = $language eq 'DE' ? $HCL_DE_READING_VALUE{$reading} : $HCL_EN_READING_VALUE{$reading};
    if (ref($specific) eq 'HASH' && exists $specific->{$value}) {
        return $specific->{$value};
    }

    # Program readings use the device-specific program dictionary.
    if ($reading =~ /^(?:SelectedProgram|ActiveProgram)$/) {
        my $t = HomeConnectLocal_TranslateDisplay($language, $device_type, 'program', $value);
        return $t if defined($t) && $t ne $value;
        return undef;
    }

    # These readings contain option/enum values, not protocol field names.
    if ($reading =~ /^(?:ProgramMode|Temperature|SpinSpeed|DryingTarget|IntensivePlus|LessIroning|LowTemperatureHygiene|MultipleSoak|Prewash|RinseHold|RinsePlus|SilentMode|SpeedPerfect|Stains|WaterPlus|WrinkleGuardBoost|ExtraDry|HygienePlus|IntensivZone|SilenceOnDemand|VarioSpeedPlus)$/) {
        my $t = HomeConnectLocal_TranslateDisplay($language, $device_type, 'value', $value);
        return $t if defined($t) && $t ne $value;
    }

    return undef;
}

1;

