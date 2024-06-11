package org.ohdsi.webapi.source;

import org.apache.commons.collections4.map.PassiveExpiringMap;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.properties.PropertyValueEncryptionUtils;
import org.ohdsi.sql.SqlTranslate;
import org.ohdsi.webapi.common.SourceMapKey;
import org.ohdsi.webapi.service.AbstractDaoService;
import org.ohdsi.webapi.shiro.management.datasource.SourceAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;

import javax.annotation.PostConstruct;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class SourceService extends AbstractDaoService {

    private final Logger logger = LoggerFactory.getLogger(SourceService.class);

    private static Collection<Source> cachedSources = null;

    @Value("${jasypt.encryptor.enabled}")
    private boolean encryptorEnabled;

    @Value("${datasource.ohdsi.schema}")
    private String schema;

    private Map<Source, Boolean> connectionAvailability = Collections.synchronizedMap(new PassiveExpiringMap<>(5000));


    private final SourceRepository sourceRepository;
    private final JdbcTemplate jdbcTemplate;
    private PBEStringEncryptor defaultStringEncryptor;
    private SourceAccessor sourceAccessor;

    public SourceService(SourceRepository sourceRepository, JdbcTemplate jdbcTemplate, PBEStringEncryptor defaultStringEncryptor, SourceAccessor sourceAccessor) {

        this.sourceRepository = sourceRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.defaultStringEncryptor = defaultStringEncryptor;
        this.sourceAccessor = sourceAccessor;
    }

    @PostConstruct
    private void postConstruct() {

        ensureSourceEncrypted();
    }

    public void ensureSourceEncrypted() {

        if (encryptorEnabled) {
            String query = "SELECT source_id, username, password FROM ${schema}.source".replaceAll("\\$\\{schema\\}", schema);
            String update = "UPDATE ${schema}.source SET username = ?, password = ? WHERE source_id = ?".replaceAll("\\$\\{schema\\}", schema);
            getTransactionTemplateRequiresNew().execute(new TransactionCallbackWithoutResult() {
                @Override
                protected void doInTransactionWithoutResult(TransactionStatus transactionStatus) {

                    jdbcTemplate.query(query, rs -> {
                        int id = rs.getInt("source_id");
                        String username = rs.getString("username");
                        String password = rs.getString("password");
                        if (username != null && !PropertyValueEncryptionUtils.isEncryptedValue(username)) {
                            username = "ENC(" + defaultStringEncryptor.encrypt(username) + ")";
                        }
                        if (password != null && !PropertyValueEncryptionUtils.isEncryptedValue(password)) {
                            password = "ENC(" + defaultStringEncryptor.encrypt(password) + ")";
                        }
                        jdbcTemplate.update(update, username, password, id);
                    });
                }
            });
        }
    }

    public Collection<Source> getSources() {

        if (cachedSources == null) {
            List<Source> sources = sourceRepository.findAll();
            Collections.sort(sources, new SortByKey());
            cachedSources = sources;
        }
        return cachedSources;
    }

    public Source findBySourceKey(final String sourceKey) {

        return sourceRepository.findBySourceKey(sourceKey);
    }

    public Source findBySourceId(final Integer sourceId) {

        return sourceRepository.findBySourceId(sourceId);
    }

    public <T> Map<T, Source> getSourcesMap(SourceMapKey<T> mapKey) {

        return getSources().stream().collect(Collectors.toMap(mapKey.getKeyFunc(), s -> s));
    }

    public void checkConnection(Source source) {

        if (source.isCheckConnection()) {
            final JdbcTemplate jdbcTemplate = getSourceJdbcTemplate(source);
            jdbcTemplate.execute(SqlTranslate.translateSql("select 1;", source.getSourceDialect()).replaceAll(";$", ""));
        }
    }

    public Source getPrioritySourceForDaimon(SourceDaimon.DaimonType daimonType) {

        List<Source> sourcesByDaimonPriority = sourceRepository.findAllSortedByDiamonPrioirty(daimonType);
        logger.debug("Found {} sources for daimon type {}.", sourcesByDaimonPriority.size(), daimonType.name());

        for (Source source : sourcesByDaimonPriority) {
            if (!(sourceAccessor.hasAccess(source) && connectionAvailability.computeIfAbsent(source, this::checkConnectionSafe))) {
                continue;
            }
            return source;
        }
        logger.debug("Found NO sources that have access.");

        return null;
    }

    public Map<SourceDaimon.DaimonType, Source> getPriorityDaimons() {

        class SourceValidator {
            private Map<Integer, Boolean> checkedSources = new HashMap<>();

            private boolean isSourceAvailable(Source source) {
                logger.debug("Checking source access via isSourceAvailable...");
                return checkedSources.computeIfAbsent(source.getSourceId(),
                        v -> sourceAccessor.hasAccess(source) && connectionAvailability.computeIfAbsent(source, SourceService.this::checkConnectionSafe));
            }
        }

        SourceValidator sourceValidator = new SourceValidator();
        Map<SourceDaimon.DaimonType, Source> priorityDaimons = new HashMap<>();
        Arrays.asList(SourceDaimon.DaimonType.values()).forEach(d -> {

            List<Source> sources = sourceRepository.findAllSortedByDiamonPrioirty(d);
            logger.debug("Found {} sources.", sources.size());
            Optional<Source> source = sources.stream().filter(sourceValidator::isSourceAvailable)
                    .findFirst();
            source.ifPresent(s -> priorityDaimons.put(d, s));
        });
        return priorityDaimons;
    }

    public Source getPriorityVocabularySource() {

        return getPrioritySourceForDaimon(SourceDaimon.DaimonType.Vocabulary);
    }

    public SourceInfo getPriorityVocabularySourceInfo() {
        Source source = getPrioritySourceForDaimon(SourceDaimon.DaimonType.Vocabulary);
        if (source == null) {
            return null;
        }
        return new SourceInfo(source);
    }

    public void invalidateCache() {

        this.cachedSources = null;
    }

    private boolean checkConnectionSafe(Source source) {

        try {
            checkConnection(source);
            logger.debug("Connection worked.");
            return true;
        } catch (CannotGetJdbcConnectionException ex) {
            logger.debug("Connection failed: {}", ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }

    private class SortByKey implements Comparator<Source> {
        private boolean isAscending;

        public SortByKey(boolean ascending) {

            isAscending = ascending;
        }

        public SortByKey() {

            this(true);
        }

        public int compare(Source s1, Source s2) {

            return s1.getSourceKey().compareTo(s2.getSourceKey()) * (isAscending ? 1 : -1);
        }
    }
}
