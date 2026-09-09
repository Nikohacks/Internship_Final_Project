# /etc/fluent/plugin/filter_ecs_normalizer.rb

require 'fluent/plugin/filter'

module Fluent::Plugin
  class EcsNormalizerFilter < Filter
    Fluent::Plugin.register_filter('ecs_normalizer', self)

    # ---------- Windows ----------

    WIN_EVENTID_CATEGORY = {
      4624 => ['authentication'],
      4625 => ['authentication'],
      4634 => ['authentication'],
      4648 => ['authentication'],
      4672 => ['authentication', 'privilege_escalation'],
      4720 => ['iam']
    }.freeze

    WIN_EVENTID_TYPE = {
      4624 => ['start'],
      4625 => ['start', 'denied'],
      4634 => ['end'],
      4648 => ['start'],
      4672 => ['info'],
      4720 => ['creation']
    }.freeze

    WIN_EVENTID_FIELD_MAP = {
      4624 => { subject_user: 'Account Name', target_user: 'Account Name_2',
                source_ip: 'Source Network Address', logon_type: 'Logon Type' },
      4625 => { subject_user: 'Account Name', target_user: 'Account Name_2',
                source_ip: 'Source Network Address', logon_type: 'Logon Type' },        
      4634 => { subject_user: 'Account Name', logon_type: 'Logon Type' },
      4648 => { subject_user: 'Account Name', target_user: 'Account Name_2',
                source_ip: 'Network Address' },
      4798 => { subject_user: 'Account Name', target_user: 'Account Name_2' }
    }.freeze

    # ---------- Linux journald ----------

    # Keyed by SYSLOG_IDENTIFIER. Extend as you cover more daemons.
    JOURNALD_IDENTIFIER_CATEGORY = {
      'sudo'   => ['authentication', 'privilege_escalation'],
      'sshd'   => ['authentication'],
      'su'     => ['authentication', 'privilege_escalation'],
      'systemd-logind' => ['authentication', 'session']
    }.freeze

    JOURNALD_IDENTIFIER_TYPE = {
      'sudo' => ['info'],
      'su'   => ['info']
    }.freeze

    SYSLOG_FACILITY_NAMES = {
      0 => 'kern', 1 => 'user', 2 => 'mail', 3 => 'daemon', 4 => 'auth',
      5 => 'syslog', 6 => 'lpr', 7 => 'news', 8 => 'uucp', 9 => 'cron',
      10 => 'authpriv', 11 => 'ftp', 16 => 'local0', 17 => 'local1',
      18 => 'local2', 19 => 'local3', 20 => 'local4', 21 => 'local5',
      22 => 'local6', 23 => 'local7'
    }.freeze

    SYSLOG_SEVERITY_NAMES = {
      0 => 'emergency', 1 => 'alert', 2 => 'critical', 3 => 'error',
      4 => 'warning', 5 => 'notice', 6 => 'informational', 7 => 'debug'
    }.freeze

    def filter(tag, time, record)
      case tag
      when 'windows.winevtlog'
        normalize_windows(record)
      when 'linux.systemd'
        normalize_linux_journald(record)
      when 'linux.syslog.system'
        normalize_linux_syslog(record)
      else
        record
      end
    end

    private

    # ================= WINDOWS =================

    def normalize_windows(record)
      parsed = parse_rendered_text(record['rendered_text'])
      event_id = parsed['EventID'].to_i
      body = parse_message_body(parsed['Message'])
      sel = WIN_EVENTID_FIELD_MAP.fetch(event_id, {})

      base = {
        'ecs.version'        => '8.11',
        'event.kind'         => 'event',
        'event.code'         => parsed['EventID'],
        'event.provider'     => parsed['ProviderName'],
        'event.dataset'      => "windows.#{parsed['Channel'].to_s.downcase}",
        'event.category'     => WIN_EVENTID_CATEGORY.fetch(event_id, []),
        'event.type'         => WIN_EVENTID_TYPE.fetch(event_id, []),
        'host.name'          => parsed['Computer'],
        'host.os.family'     => 'windows',
        'process.pid'        => parsed['ProcessID'],
        'winlog.channel'     => parsed['Channel'],
        'winlog.record_id'   => parsed['EventRecordID'],
        'winlog.activity_id' => parsed['ActivityID'],
        'log.level'          => parsed['Level'],
        'message'            => parsed['Message'],
        'event.original'     => record.to_json
      }

      base['user.name']         = body[sel[:subject_user]] if sel[:subject_user]
      base['user.target.name']  = body[sel[:target_user]] if sel[:target_user]
      base['related.user']      = [body[sel[:subject_user]], body[sel[:target_user]]].compact.uniq if sel[:target_user]
      base['source.ip']         = body[sel[:source_ip]] if sel[:source_ip] && body[sel[:source_ip]] != '-'
      base['winlog.logon.type'] = body[sel[:logon_type]] if sel[:logon_type]

      base
    end

    def parse_rendered_text(text)
      fields = {}
      current_key = nil
      text.to_s.each_line do |line|
        if line =~ /^([A-Za-z][A-Za-z0-9_]*)=(.*)$/
          current_key = $1
          fields[current_key] = $2
        elsif current_key
          fields[current_key] += "\n" + line.chomp
        end
      end
      fields.transform_values(&:strip)
    end

    def parse_message_body(message)
      fields = {}
      message.to_s.each_line do |line|
        if line =~ /^\s*([A-Za-z][A-Za-z0-9 \(\)\/]*?):\s+(\S.*)$/
          label = $1.strip
          value = $2.strip
          key = fields.key?(label) ? "#{label}_2" : label
          fields[key] = value
        end
      end
      fields
    end

    # ================= LINUX: journald =================

    def normalize_linux_journald(record)
      identifier = record['SYSLOG_IDENTIFIER'] || record['_COMM']
      facility   = record['SYSLOG_FACILITY'].to_i
      priority   = record['PRIORITY'].to_i

      base = {
        'ecs.version'          => '8.11',
        'event.kind'           => 'event',
        'event.dataset'        => 'linux.journald',
        'event.provider'       => identifier,
        'event.category'       => JOURNALD_IDENTIFIER_CATEGORY.fetch(identifier, []),
        'event.type'           => JOURNALD_IDENTIFIER_TYPE.fetch(identifier, []),
        'host.name'            => record['_HOSTNAME'],
        'host.os.family'       => 'linux',
        'process.name'         => identifier,
        'process.executable'   => record['_EXE'],
        'process.pid'          => record['_PID'],
        'process.command_line' => record['_CMDLINE'],
        'user.id'               => record['_UID'],
        'group.id'               => record['_GID'],
        'log.syslog.priority'     => priority,
        'log.syslog.facility.code'=> facility,
        'log.syslog.facility.name'=> SYSLOG_FACILITY_NAMES[facility],
        'log.level'                => SYSLOG_SEVERITY_NAMES[priority],
        'message'                  => record['MESSAGE'],
        'event.original'           => record.to_json
      }

      extract_journald_user(base, record['MESSAGE'], identifier)
      base
    end

    # pam_unix lines commonly carry "for user X" / "by (uid=N)" — cheap,
    # high-value extraction without full PAM message parsing.
    def extract_journald_user(base, message, identifier)
      return unless message

      case identifier
      when 'sudo', 'su'
        if message =~ /for user ([^\s(]+)/
          base['user.target.name'] = $1
        end
        if message =~ /by \(uid=(\d+)\)/
          base['user.id'] = $1
        end
      when 'sshd'
        if message =~ /Failed password for (invalid user )?(\S+) from (\S+) port (\d+)/
          base['user.target.name'] = $2
          base['source.ip']        = $3
          base['source.port']      = $4
          base['event.outcome']    = 'failure'
          base['event.type']       = ['start', 'denied']
        elsif message =~ /Accepted password for (\S+) from (\S+) port (\d+)/
          base['user.target.name'] = $1
          base['source.ip']        = $2
          base['source.port']      = $3
          base['event.outcome']    = 'success'
          base['event.type']       = ['start']
        end
      end
    end

    # ================= LINUX: syslog (RFC3164 tail) =================

    def normalize_linux_syslog(record)
      {
        'ecs.version'       => '8.11',
        'event.kind'        => 'event',
        'event.dataset'     => 'linux.syslog',
        'event.provider'    => record['ident'],
        'event.category'    => [],
        'event.type'        => [],
        'host.name'         => record['host'],
        'host.os.family'    => 'linux',
        'process.name'      => record['ident'],
        'process.pid'       => record['pid'],
        'message'           => record['message'],
        'event.original'    => record.to_json
      }
    end
  end
end