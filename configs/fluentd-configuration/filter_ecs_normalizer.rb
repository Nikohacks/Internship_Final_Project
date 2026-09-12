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

    JOURNALD_IDENTIFIER_CATEGORY = {
      'sudo'           => ['authentication', 'privilege_escalation'],
      'sshd'           => ['authentication'],
      'su'             => ['authentication', 'privilege_escalation'],
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
      return record unless record.is_a?(Hash)

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
    rescue StandardError => e
      log.warn "ecs_normalizer failed to parse record: #{e.message}"
      record
    end

    private

    # ================= WINDOWS =================

    def normalize_windows(record)
      # Extract fields directly from record if rendered_text is missing or empty
      parsed = if record['rendered_text'].to_s.strip.empty?
                 extract_windows_from_record(record)
               else
                 parse_rendered_text(record['rendered_text'])
               end

      # Merge top-level record keys as fallback for missing parsed values
      parsed['EventID']       ||= record['event_id'] || record['EventID']
      parsed['ProviderName']  ||= record['provider'] || record['Provider Name']
      parsed['Channel']       ||= record['channel'] || record['Channel'] || 'Security'
      parsed['Computer']      ||= record['computer'] || record['Computer']
      parsed['ProcessID']     ||= record['process_id'] || record['ProcessID']
      parsed['EventRecordID'] ||= record['event_record_id'] || record['EventRecordID']
      parsed['ActivityID']    ||= record['activity_id'] || record['ActivityID']
      parsed['Level']         ||= record['level'] || record['Level']
      parsed['Message']       ||= record['message'] || record['Message'] || record['rendered_text']

      event_id = parsed['EventID'].to_i
      body = parse_message_body(parsed['Message'])
      sel = WIN_EVENTID_FIELD_MAP.fetch(event_id, {})

      channel_str = parsed['Channel'].to_s.downcase

      base = {
        'ecs.version'        => '8.11',
        'event.kind'         => 'event',
        'event.code'         => parsed['EventID'].to_s,
        'event.provider'     => parsed['ProviderName'].to_s,
        'event.dataset'      => "windows.#{channel_str}",
        'event.category'     => WIN_EVENTID_CATEGORY.fetch(event_id, []),
        'event.type'         => WIN_EVENTID_TYPE.fetch(event_id, []),
        'host.name'          => parsed['Computer'].to_s,
        'host.os.family'     => 'windows',
        'process.pid'        => parsed['ProcessID'],
        'winlog.channel'     => parsed['Channel'].to_s,
        'winlog.record_id'   => parsed['EventRecordID'],
        'winlog.activity_id' => parsed['ActivityID'],
        'log.level'          => parsed['Level'].to_s,
        'message'            => parsed['Message'].to_s,
        'event.original'     => record.to_json
      }

      base['user.name']         = body[sel[:subject_user]] if sel[:subject_user]
      base['user.target.name']  = body[sel[:target_user]] if sel[:target_user]
      base['related.user']      = [body[sel[:subject_user]], body[sel[:target_user]]].compact.uniq if sel[:target_user]
      base['source.ip']         = body[sel[:source_ip]] if sel[:source_ip] && body[sel[:source_ip]] != '-'
      base['winlog.logon.type'] = body[sel[:logon_type]] if sel[:logon_type]

      base
    end

    def extract_windows_from_record(record)
      {
        'EventID'       => record['event_id'] || record['EventID'],
        'ProviderName'  => record['provider'] || record['Provider Name'],
        'Channel'       => record['channel'] || record['Channel'],
        'Computer'      => record['computer'] || record['Computer'],
        'ProcessID'     => record['process_id'] || record['ProcessID'],
        'EventRecordID' => record['event_record_id'] || record['EventRecordID'],
        'ActivityID'    => record['activity_id'] || record['ActivityID'],
        'Level'         => record['level'] || record['Level'],
        'Message'       => record['message'] || record['Message']
      }
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
        'ecs.version'             => '8.11',
        'event.kind'              => 'event',
        'event.dataset'           => 'linux.journald',
        'event.provider'          => identifier.to_s,
        'event.category'          => JOURNALD_IDENTIFIER_CATEGORY.fetch(identifier, []),
        'event.type'              => JOURNALD_IDENTIFIER_TYPE.fetch(identifier, []),
        'host.name'               => record['_HOSTNAME'].to_s,
        'host.os.family'          => 'linux',
        'process.name'            => identifier.to_s,
        'process.executable'      => record['_EXE'].to_s,
        'process.pid'             => record['_PID'],
        'process.command_line'    => record['_CMDLINE'].to_s,
        'user.id'                 => record['_UID'],
        'group.id'                => record['_GID'],
        'log.syslog.priority'     => priority,
        'log.syslog.facility.code'=> facility,
        'log.syslog.facility.name'=> SYSLOG_FACILITY_NAMES[facility],
        'log.level'               => SYSLOG_SEVERITY_NAMES[priority],
        'message'                 => record['MESSAGE'].to_s,
        'event.original'          => record.to_json
      }

      extract_journald_user(base, record['MESSAGE'].to_s, identifier)
      base
    end

    def extract_journald_user(base, message, identifier)
      return if message.empty?

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
        'event.provider'    => record['ident'].to_s,
        'event.category'    => [],
        'event.type'        => [],
        'host.name'         => record['host'].to_s,
        'host.os.family'    => 'linux',
        'process.name'      => record['ident'].to_s,
        'process.pid'       => record['pid'],
        'message'           => record['message'].to_s,
        'event.original'    => record.to_json
      }
    end
  end
end