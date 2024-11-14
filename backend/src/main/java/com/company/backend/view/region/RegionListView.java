package com.company.backend.view.region;

import com.company.backend.entity.Region;
import com.vaadin.flow.router.Route;
import io.jmix.flowui.view.*;


@Route(value = "regions", layout = DefaultMainViewParent.class)
@ViewController(id = "Region.list")
@ViewDescriptor(path = "region-list-view.xml")
@LookupComponent("regionsDataGrid")
@DialogMode(width = "64em")
public class RegionListView extends StandardListView<Region> {
}