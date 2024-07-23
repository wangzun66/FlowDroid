package soot.jimple.infoflow.aliasing.sparse;

import boomerang.scene.sparse.SparseCFGCache;
import soot.jimple.infoflow.InfoflowManager;

public class AdaptiveSparseBoomerangAliasStrategy extends AbstractBoomerangAliasStrategy{

    public AdaptiveSparseBoomerangAliasStrategy(InfoflowManager manager) {
        super(manager);
    }

    @Override
    public StrategyDeciderManager getSparseAliasManager() {
        return StrategyDeciderManager.getInstance(SparseCFGCache.SparsificationStrategy.ADAPTIVE);
    }
}
