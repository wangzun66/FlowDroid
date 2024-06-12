package soot.jimple.infoflow.aliasing.sparse;

import boomerang.scene.sparse.SparseCFGCache;
import soot.jimple.infoflow.InfoflowManager;

public class DynamicSparseBoomerangAliasStrategy extends AbstractBoomerangAliasStrategy{

    public DynamicSparseBoomerangAliasStrategy(InfoflowManager manager) {
        super(manager);
    }

    @Override
    public StrategyDeciderManager getSparseAliasManager() {
        return StrategyDeciderManager.getInstance(SparseCFGCache.SparsificationStrategy.DYNAMIC);
    }
}
