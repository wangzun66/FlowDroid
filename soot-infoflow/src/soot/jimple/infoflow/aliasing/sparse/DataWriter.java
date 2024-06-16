package soot.jimple.infoflow.aliasing.sparse;

import boomerang.BackwardQuery;
import boomerang.datacollection.DataCollection;
import boomerang.datacollection.DecisionLog;
import boomerang.datacollection.MethodLog;
import boomerang.datacollection.QueryLog;
import boomerang.scene.sparse.SparseAliasingCFG;
import boomerang.scene.sparse.SparseCFGCache;
import boomerang.scene.sparse.eval.SparseCFGQueryLog;
import core.fx.base.*;
import core.fx.methodbased.AllocationCount;
import core.fx.methodbased.MethodStmtCount;
import core.fx.methodbased.ProportionOfRelevantStmts;
import core.fx.methodstmtbased.ProportionOfRelevantStmtsBeforeStmt;
import core.fx.methodstmtbased.ProportionOfVisitedMethodBeforeStmt;
import core.fx.methodstmtbased.StmtDepthProportion;
import core.fx.methodvarbased.ProportionOfVisitedMethod;
import core.fx.methodvarbased.RelatedTypesCount;
import core.fx.methodvarbased.TypeHierarchySize;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.Stmt;
import soot.jimple.internal.JReturnStmt;
import soot.jimple.internal.JReturnVoidStmt;

import java.io.*;
import java.util.*;

public class DataWriter {

    private final String OUT_PUT_DIR = "./method_raw_result";
    private static File file;
    private static String targetProgram;
    private List<FeatureExtractionUnit> featureExtractors = new ArrayList<>();
    private Map<String, Set<String>> visitedQueries = new HashMap<>();
    private int count = 0;


    private final SparseCFGCache.SparsificationStrategy sparsificationStrategy;

    public DataWriter(SparseCFGCache.SparsificationStrategy sparsificationStrategy) {
        this.sparsificationStrategy = sparsificationStrategy;
        createFeaturesExtractor();
    }

    public static void setTargetProgram(String apkname){
        targetProgram = apkname;
    }

    public void write(){
        createFileName();
        //write head
        String head = createHeadForDataCollection();
        try{
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), "UTF-8"));
            writer.write(head);
            writer.flush();
            writer.close();
        }catch (IOException e) {
            e.printStackTrace();
        }
        //write data
        try{
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true), "UTF-8"));
            int queryCount = StrategyDeciderManager.getInstance(sparsificationStrategy).getQueryCount();
            for(int i = 0; i < queryCount; i++ ){
                String prefix = createPrefixForQuery(i);
                QueryLog queryLog = DataCollection.getInstance().getQueryLog(i);
                List<String> data = arrangeDataForMethods(prefix, queryLog);
                for(String item :  data){
                    writer.write(item);
                }
            }
            writer.flush();
            writer.close();
        }catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void writeResult(){
        createFileName();
        //write head
        String head = createHeadForResultComparison();
        try{
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), "UTF-8"));
            writer.write(head);
            writer.flush();
            writer.close();
        }catch (IOException e) {
            e.printStackTrace();
        }
        //write data
        try{
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true), "UTF-8"));
            int queryCount = StrategyDeciderManager.getInstance(sparsificationStrategy).getQueryCount();
            for(int i = 0; i < queryCount; i++ ){
                String prefix = createPrefixForQuery(i);
                QueryLog queryLog = DataCollection.getInstance().getQueryLog(i);
                List<String> data = arrangeResultForMethods(prefix, queryLog);
                for(String item :  data){
                    writer.write(item);
                }
            }
            writer.flush();
            writer.close();
        }catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createFileName(){
        int toIndex = targetProgram.lastIndexOf(".apk");
        String apk_name = targetProgram.substring(0, toIndex);
        String file_name = apk_name+ "_" + sparsificationStrategy + "_1.csv";
        File dir = new File(OUT_PUT_DIR);
        if (!dir.exists()) {
            dir.mkdir();
        }
        file = new File(OUT_PUT_DIR + File.separator + file_name);
        int fileCount = 1;
        while(file.exists() && fileCount<5){
            fileCount ++;
            file_name = apk_name+ "_" + sparsificationStrategy + "_" + fileCount+".csv";
            file = new File(OUT_PUT_DIR + File.separator + file_name);
        }
        if(file.exists()){
            throw new RuntimeException("The analysis for " + targetProgram + " is finished");
        }
    }

    private String createHeadForResultComparison(){
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("queryId");
        stringBuilder.append(",");
        stringBuilder.append("queryInfo");
        stringBuilder.append(",");
        stringBuilder.append("queryTime");
        stringBuilder.append(",");
        stringBuilder.append("PDSBuildingTime");
        stringBuilder.append(",");
        stringBuilder.append("aliasesSearchingTime");
        stringBuilder.append(",");
        stringBuilder.append("methodSignature");
        stringBuilder.append(",");
        stringBuilder.append("decision");
        stringBuilder.append(",");
        stringBuilder.append("built/retrieved");
        stringBuilder.append(",");
        stringBuilder.append("scfg");
        stringBuilder.append(",");
        stringBuilder.append("sparseDegree");
        stringBuilder.append(",");
        stringBuilder.append("visitedTime");
        stringBuilder.append(System.lineSeparator());
        return stringBuilder.toString();
    }

    private String createHeadForDataCollection(){
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("queryId");
        stringBuilder.append(",");
        stringBuilder.append("queryInfo");
        stringBuilder.append(",");
        stringBuilder.append("queryTime");
        stringBuilder.append(",");
        stringBuilder.append("PDSBuildingTime");
        stringBuilder.append(",");
        stringBuilder.append("aliasesSearchingTime");
        stringBuilder.append(",");
        stringBuilder.append("methodSignature");
        stringBuilder.append(",");
        stringBuilder.append("built/retrieved");
        stringBuilder.append(",");
        stringBuilder.append("scfg");
        stringBuilder.append(",");
        stringBuilder.append("sparseDegree");
        stringBuilder.append(",");
        stringBuilder.append("hasSameReturnType");
        stringBuilder.append(",");
        stringBuilder.append("isTailStmt");
        stringBuilder.append(",");
        stringBuilder.append("methodStmtsCount");
        stringBuilder.append(",");
        stringBuilder.append("relatedTypeCount");
        stringBuilder.append(",");
        stringBuilder.append("typeHierarchySize");
        stringBuilder.append(",");
        stringBuilder.append("propOfVisitedMethod");
        stringBuilder.append(",");
        stringBuilder.append("propOfRStmt");
        stringBuilder.append(",");
        stringBuilder.append("stmtDepth");
        stringBuilder.append(",");
        stringBuilder.append("allocCount");
        stringBuilder.append(",");
        stringBuilder.append("propOfStmtBeforeQS");
        stringBuilder.append(",");
        stringBuilder.append("propOfVMBeforeQS");
        stringBuilder.append(",");
        stringBuilder.append("visitedTime");
        stringBuilder.append(System.lineSeparator());
        return stringBuilder.toString();
    }

    private String createPrefixForQuery(int id){
        StringBuilder sb = new StringBuilder();
        sb.append(count);
        sb.append(",");
        BackwardQuery query = StrategyDeciderManager.getInstance(sparsificationStrategy).getId2Query().get(id);
        sb.append(query.getInfo().replace(',', ' '));
        sb.append(",");
        String queryTime = String.valueOf(StrategyDeciderManager.getInstance(sparsificationStrategy).getId2QueryTime().get(id));
        sb.append(queryTime);
        sb.append(",");
        String pdsTime = String.valueOf(StrategyDeciderManager.getInstance(sparsificationStrategy).getId2PDSBuildingTime().get(id));
        sb.append(pdsTime);
        sb.append(",");
        String aliasingTime = String.valueOf(StrategyDeciderManager.getInstance(sparsificationStrategy).getId2AliasSearchingTime().get(id));
        sb.append(aliasingTime);
        sb.append(",");
        return sb.toString();
    }

    private List<String> arrangeResultForMethods(String prefix, QueryLog queryLog){
        List<String> result = new ArrayList<>();

        //arrange visited time
        Map<SootMethod, Long> method2Time = new HashMap<>();
        List<MethodLog> logs = queryLog.getMethodLogs();
        if(logs == null){
            return result;
        }
        for(MethodLog log : logs){
            SootMethod method = log.getMethod();
            Long time = log.getDuration().toNanos();
            if(method2Time.containsKey(method)){
                time += method2Time.get(method);
            }
            method2Time.put(method, time);
        }
        //delete repeated queries
        if(visitedQueries.keySet().contains(queryLog.getQuery().getInfo())){
            assert visitedQueries.get(queryLog.getQuery().getInfo()).size() == method2Time.keySet().size();
            for(SootMethod method : method2Time.keySet()){
                assert visitedQueries.get(queryLog.getQuery().getInfo()).contains(method.getSignature());
            }
            return result;
        }
        Set<String> ms = new HashSet<>();
        for(SootMethod method : method2Time.keySet()){
            ms.add(method.getSignature());
        }
        visitedQueries.put(queryLog.getQuery().getInfo(), ms);
        count++;
        //arrange decision logs
        Map<String, Integer> method2Decision = new HashMap<>();
        List<DecisionLog> decisionLogs = queryLog.getDecisionLogs();
        for(DecisionLog log : decisionLogs){
            method2Decision.put(log.getMethodSig(), log.getDecision());
        }
        //arrange scfg logs
        Map<SootMethod, String> method2Result = new HashMap<>();
        List<SparseCFGQueryLog> scfgLogs = queryLog.getSCFGLogs();
        for(SparseCFGQueryLog scfgLog : scfgLogs){
            SootMethod method = scfgLog.getMethod();
            StringBuilder sb = new StringBuilder();
            boolean retrieved = scfgLog.isRetrievedFromCache();
            sb.append(prefix);
            sb.append(method.getSignature().replace(',', ' '));
            sb.append(",");
            if(sparsificationStrategy == SparseCFGCache.SparsificationStrategy.DYNAMIC){
                sb.append(method2Decision.get(method.getSignature()));
            }else {
                sb.append("NN");
            }
            sb.append(",");
            if(retrieved){
                sb.append("retrieved");
                sb.append(",");
                sb.append(scfgLog.getScfg());
                sb.append(",");
                sb.append("NN");
            }else {
                sb.append("built");
                sb.append(",");
                sb.append(scfgLog.getScfg());
                sb.append(",");
                double degree = (double) scfgLog.getFinalStmtCount()/(double) scfgLog.getInitialStmtCount();
                sb.append(String.format("%.2f", degree));
            }
            sb.append(",");
            sb.append(method2Time.get(method));
            sb.append(System.lineSeparator());
            method2Result.put(method, sb.toString());
        }
        //arrange to data
        for(SootMethod method : method2Result.keySet()){
            result.add(method2Result.get(method));
        }
        for(Map.Entry<SootMethod, Long> entry : method2Time.entrySet()){
            if(!method2Result.containsKey(entry.getKey())){
                StringBuilder sb = new StringBuilder();
                sb.append(prefix);
                sb.append(entry.getKey().getSignature().replace(',', ' '));
                sb.append(",");
                sb.append("NN,NN,NN,NN,");
                sb.append(entry.getValue());
                sb.append(System.lineSeparator());
                result.add(sb.toString());
            }
        }
        return result;
    }

    private List<String> arrangeDataForMethods(String prefix, QueryLog queryLog){
        List<String> result = new ArrayList<>();

        //arrange visited time
        Map<SootMethod, Long> method2Time = new HashMap<>();
        List<MethodLog> logs = queryLog.getMethodLogs();
        if(logs == null){
            return result;
        }
        for(MethodLog log : logs){
            SootMethod method = log.getMethod();
            Long time = log.getDuration().toNanos();
            if(method2Time.containsKey(method)){
                time += method2Time.get(method);
            }
            method2Time.put(method, time);
        }
        if(visitedQueries.keySet().contains(queryLog.getQuery().getInfo())){
            assert visitedQueries.get(queryLog.getQuery().getInfo()).size() == method2Time.keySet().size();
            for(SootMethod method : method2Time.keySet()){
                assert visitedQueries.get(queryLog.getQuery().getInfo()).contains(method.getSignature());
            }
            return result;
        }
        Set<String> ms = new HashSet<>();
        for(SootMethod method : method2Time.keySet()){
            ms.add(method.getSignature());
        }
        visitedQueries.put(queryLog.getQuery().getInfo(), ms);
        count++;
        //arrange scfg logs
        Map<SootMethod, String> method2Result = new HashMap<>();
        List<SparseCFGQueryLog> scfgLogs = queryLog.getSCFGLogs();
        for(SparseCFGQueryLog scfgLog : scfgLogs){
            SootMethod method = scfgLog.getMethod();
            StringBuilder sb = new StringBuilder();
            boolean retrieved = scfgLog.isRetrievedFromCache();
            sb.append(prefix);
            sb.append(method.getSignature().replace(',', ' '));
            sb.append(",");
            if(retrieved){
                sb.append("retrieved");
                sb.append(",");
                sb.append(scfgLog.getScfg());
                sb.append(",");
                sb.append("NN");
            }else {
                sb.append("built");
                sb.append(",");
                sb.append(scfgLog.getScfg());
                sb.append(",");
                double degree = (double) scfgLog.getFinalStmtCount()/(double) scfgLog.getInitialStmtCount();
                sb.append(String.format("%.2f", degree));
            }
            sb.append(",");
            if(!retrieved){
                if(sparsificationStrategy == SparseCFGCache.SparsificationStrategy.TYPE_BASED){
                    sb.append(hasSameReturnedType(method, scfgLog.getValue()));
                    sb.append(",");
                    sb.append("NN");
                }else if(sparsificationStrategy == SparseCFGCache.SparsificationStrategy.ALIAS_AWARE){
                    sb.append("NN");
                    sb.append(",");
                    sb.append(isTailStmt(scfgLog.getStmt()));
                }
            }else {
                sb.append("NN");
                sb.append(",");
                sb.append("NN");
            }
            sb.append(",");
            List<Feature> features = extract(method, scfgLog.getValue(), scfgLog.getStmt());
            sb.append(convertFeaturesToData(features));
            sb.append(method2Time.get(method));
            sb.append(System.lineSeparator());
            method2Result.put(method, sb.toString());
        }

        //arrange to data
        for(SootMethod method : method2Result.keySet()){
            result.add(method2Result.get(method));
            //writeMethodBody(method);
            //writeSCFGBody(method);
        }

        for(Map.Entry<SootMethod, Long> entry : method2Time.entrySet()){
            if(!method2Result.containsKey(entry.getKey())){
                StringBuilder sb = new StringBuilder();
                sb.append(prefix);
                sb.append(entry.getKey().getSignature().replace(',', ' '));
                sb.append(",");
                sb.append("NN,NN,NN,NN,NN,NN,NN,NN,NN,NN,NN,NN,NN,NN,");
                sb.append(entry.getValue());
                sb.append(System.lineSeparator());
                result.add(sb.toString());
                //writeMethodBody(entry.getKey());
            }
        }
        return result;
    }

    private boolean hasSameReturnedType(SootMethod sm, Value value){
        if(sm.getReturnType() != null){
            if(sm.getReturnType().equals(value.getType())){
                return true;
            }
        }
        return false;
    }

    private boolean isTailStmt(Stmt stmt){
        if(stmt instanceof JReturnStmt || stmt instanceof JReturnVoidStmt){
            return true;
        }
        return false;
    }

    private void createFeaturesExtractor(){
        featureExtractors.add(new MethodStmtCount());
        featureExtractors.add(new RelatedTypesCount());
        featureExtractors.add(new TypeHierarchySize());
        featureExtractors.add(new ProportionOfVisitedMethod());
        featureExtractors.add(new ProportionOfRelevantStmts());
        featureExtractors.add(new StmtDepthProportion());
        featureExtractors.add(new AllocationCount());
        featureExtractors.add(new ProportionOfRelevantStmtsBeforeStmt());
        featureExtractors.add(new ProportionOfVisitedMethodBeforeStmt());
    }

    private List<Feature> extract(SootMethod method, Value value, Stmt stmt) {
        List<Feature> features = new ArrayList<>();

        for (FeatureExtractionUnit extractor : featureExtractors) {
            Feature feature = null;
            if (extractor instanceof MethodFEU) {
                feature = ((MethodFEU<?>) extractor).extract(method);
            } else if (extractor instanceof MethodVarFEU) {
                if(value != null){
                    feature = ((MethodVarFEU<?>) extractor).extract(method, value);
                }else {
                    feature = null;
                }

            } else if (extractor instanceof MethodStmtFEU) {
                if(stmt != null){
                    feature = ((MethodStmtFEU<?>) extractor).extract(method, stmt);
                }else {
                    feature = null;
                }
            }
            features.add(feature);
        }
        return features;
    }

    private String convertFeaturesToData(List<Feature> features) {
        StringBuilder sb = new StringBuilder();
        for (Feature feature : features) {
            if(feature != null){
                sb.append(feature.getValue().toString());
            }else{
                sb.append("NN");
            }
            sb.append(",");
        }
        return sb.toString();
    }

    private void writeMethodBody(SootMethod method) {
        int toIndex = targetProgram.lastIndexOf(".apk");
        String apk_name = targetProgram.substring(0, toIndex);
        File dir = new File(OUT_PUT_DIR+File.separator+ "Methods" + File.separator + apk_name);
        if(!dir.exists()){
            dir.mkdir();
        }
        String fileName = method.getDeclaringClass().toString() + "." + method.getName() + ".txt";
        File methodFile = new File(dir + File.separator + fileName);
        if(methodFile.exists()){
            return;
        }
        try{
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(methodFile), "UTF-8"));
            writer.write(method.getActiveBody().toString());
            writer.flush();
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private void writeSCFGBody(SootMethod method) {
        Map<String, Map<String, Set<SparseAliasingCFG>> > cache = SparseCFGCache.getInstance(sparsificationStrategy, true).getCache();
        if(!cache.containsKey(method.getSignature())){
            return;
        }
        int toIndex = targetProgram.lastIndexOf(".apk");
        String apk_name = targetProgram.substring(0, toIndex);
        File dir = new File(OUT_PUT_DIR+File.separator+ "Methods" + File.separator + apk_name + File.separator + "SCFG_" + sparsificationStrategy);
        if(!dir.exists()){
            dir.mkdir();
        }
        Map<String, Set<SparseAliasingCFG>> queryInfo2SCFG = cache.get(method.getSignature());
        String filename = method.getDeclaringClass() + "." + method.getName();
        int i= 0;
        for(Map.Entry<String, Set<SparseAliasingCFG>> entry : queryInfo2SCFG.entrySet()){
            for(SparseAliasingCFG scfg : entry.getValue()){
                String name = filename+ "_" + i;
                File methodFile = new File(dir + File.separator + name);
                i++;
                if(methodFile.exists()){
                    return;
                }
                try{
                    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(methodFile, true), "UTF-8"));
                    writer.write(entry.getKey() + System.lineSeparator());
                    for(Unit stmt : scfg.getGraph().nodes()){
                        writer.write(stmt.toString() + System.lineSeparator());
                    }
                    writer.flush();
                    writer.close();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
    }
}
