package com.company.backend.view.region;

import com.company.backend.entity.Region;
import com.vaadin.flow.router.Route;
import io.jmix.flowui.view.*;

@Route(value = "regions/:id", layout = DefaultMainViewParent.class)
@ViewController(id = "Region.detail")
@ViewDescriptor(path = "region-detail-view.xml")
@EditedEntityContainer("regionDc")
public class RegionDetailView extends StandardDetailView<Region> {
}